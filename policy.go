package yabber

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	defaultRateLimitMaxKeys     = 10_000
	defaultRateLimitIdleTimeout = 10 * time.Minute
)

type compiledPolicy struct {
	middleware Middleware
	definition Policy
}

func compilePolicies(input []Policy, previous map[string]compiledPolicy) (map[string]compiledPolicy, error) {
	result := make(map[string]compiledPolicy, len(input))
	for _, policy := range input {
		if policy.Name == "" {
			return nil, errors.New("policy name is required")
		}
		if _, exists := result[policy.Name]; exists {
			return nil, fmt.Errorf("duplicate policy name %q", policy.Name)
		}
		if existing, ok := previous[policy.Name]; ok && reflect.DeepEqual(existing.definition, policy) {
			result[policy.Name] = existing
			continue
		}

		var middleware []Middleware
		if policy.Request != nil {
			items, err := requestMiddleware(policy.Name, *policy.Request)
			if err != nil {
				return nil, err
			}
			middleware = append(middleware, items...)
		}
		if policy.RateLimit != nil {
			item, err := newRateLimitMiddleware(policy.Name, *policy.RateLimit)
			if err != nil {
				return nil, err
			}
			middleware = append(middleware, item)
		}
		if policy.Concurrency != nil {
			item, err := newConcurrencyMiddleware(policy.Name, *policy.Concurrency)
			if err != nil {
				return nil, err
			}
			middleware = append(middleware, item)
		}
		if len(middleware) == 0 {
			return nil, fmt.Errorf("policy %q has no behavior", policy.Name)
		}
		policyName := policy.Name
		policyMiddleware := append([]Middleware(nil), middleware...)
		result[policy.Name] = compiledPolicy{
			middleware: func(next http.Handler) http.Handler {
				wrapped := chain(next, policyMiddleware...)
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					state := requestStateFromContext(r.Context())
					if state != nil {
						if _, exists := state.Applied[policyName]; exists {
							next.ServeHTTP(w, r)
							return
						}
						state.Applied[policyName] = struct{}{}
					}
					wrapped.ServeHTTP(w, r)
				})
			},
			definition: policy,
		}
	}
	return result, nil
}

func applyPolicies(
	handler http.Handler,
	names []string,
	policies map[string]compiledPolicy,
	scope string,
) (http.Handler, error) {
	for i := len(names) - 1; i >= 0; i-- {
		policy, ok := policies[names[i]]
		if !ok {
			return nil, fmt.Errorf("%s references unknown policy %q", scope, names[i])
		}
		handler = policy.middleware(handler)
	}
	return handler, nil
}

func requestMiddleware(name string, config RequestPolicy) ([]Middleware, error) {
	if config.MaxBodyBytes < 0 {
		return nil, fmt.Errorf("policy %q has negative max_body_bytes", name)
	}
	if config.Timeout < 0 {
		return nil, fmt.Errorf("policy %q has negative timeout", name)
	}
	var result []Middleware
	if config.Timeout > 0 {
		result = append(result, func(next http.Handler) http.Handler {
			return http.TimeoutHandler(next, config.Timeout, "gateway timeout\n")
		})
	}
	if config.MaxBodyBytes > 0 {
		result = append(result, func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ContentLength > config.MaxBodyBytes {
					reject(w, r, name+":body", http.StatusRequestEntityTooLarge, "request body too large")
					return
				}
				r.Body = http.MaxBytesReader(w, r.Body, config.MaxBodyBytes)
				next.ServeHTTP(w, r)
			})
		})
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("policy %q request policy has no limit", name)
	}
	return result, nil
}

type rateLimitEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type rateLimitMiddleware struct {
	name        string
	limit       rate.Limit
	burst       int
	key         string
	maxKeys     int
	idleTimeout time.Duration
	retryAfter  int
	mu          sync.Mutex
	entries     map[string]*rateLimitEntry
	requests    uint64
}

func newRateLimitMiddleware(name string, config RateLimitPolicy) (Middleware, error) {
	if config.RequestsPerSecond <= 0 {
		return nil, fmt.Errorf("policy %q rate limit must be positive", name)
	}
	if config.Burst <= 0 {
		return nil, fmt.Errorf("policy %q rate limit burst must be positive", name)
	}
	key := strings.ToLower(strings.TrimSpace(config.Key))
	if key == "" {
		key = "client_ip"
	}
	if key != "client_ip" && key != "global" {
		return nil, fmt.Errorf("policy %q has unsupported rate limit key %q", name, config.Key)
	}
	maxKeys := config.MaxKeys
	if maxKeys == 0 {
		maxKeys = defaultRateLimitMaxKeys
	}
	if maxKeys < 0 {
		return nil, fmt.Errorf("policy %q rate limit max_keys must be positive", name)
	}
	idleTimeout := config.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = defaultRateLimitIdleTimeout
	}
	if idleTimeout < 0 {
		return nil, fmt.Errorf("policy %q rate limit idle_timeout must be positive", name)
	}
	limiter := &rateLimitMiddleware{
		name: name, limit: rate.Limit(config.RequestsPerSecond),
		burst: config.Burst, key: key, maxKeys: maxKeys,
		idleTimeout: idleTimeout,
		retryAfter:  max(1, int(math.Ceil(1/config.RequestsPerSecond))),
		entries:     make(map[string]*rateLimitEntry),
	}
	return limiter.wrap, nil
}

func (m *rateLimitMiddleware) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := "global"
		if m.key == "client_ip" {
			key = ClientIP(r)
			if key == "" {
				key = "unknown"
			}
		}
		if !m.allow(key, time.Now()) {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", m.retryAfter))
			reject(w, r, m.name+":rate", http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (m *rateLimitMiddleware) allow(key string, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests++
	if m.requests%256 == 0 {
		m.cleanup(now)
	}
	entry := m.entries[key]
	if entry == nil {
		if len(m.entries) >= m.maxKeys {
			m.cleanup(now)
			if len(m.entries) >= m.maxKeys {
				return false
			}
		}
		entry = &rateLimitEntry{limiter: rate.NewLimiter(m.limit, m.burst)}
		m.entries[key] = entry
	}
	entry.lastSeen = now
	return entry.limiter.AllowN(now, 1)
}

func (m *rateLimitMiddleware) cleanup(now time.Time) {
	for key, entry := range m.entries {
		if now.Sub(entry.lastSeen) > m.idleTimeout {
			delete(m.entries, key)
		}
	}
}

func newConcurrencyMiddleware(name string, config ConcurrencyPolicy) (Middleware, error) {
	if config.Max <= 0 {
		return nil, fmt.Errorf("policy %q concurrency max must be positive", name)
	}
	semaphore := make(chan struct{}, config.Max)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
				next.ServeHTTP(w, r)
			default:
				w.Header().Set("Retry-After", "1")
				reject(w, r, name+":concurrency", http.StatusServiceUnavailable, "concurrency limit exceeded")
			}
		})
	}, nil
}
