package yabber

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"reflect"
	"strconv"
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
	definition Policy
	middleware []Middleware
}

// compilePolicies builds every policy. A policy whose definition is unchanged
// from prev is reused, so its rate-limit buckets and concurrency slots
// survive Apply.
func compilePolicies(input []Policy, prev map[string]*compiledPolicy) (map[string]*compiledPolicy, error) {
	result := make(map[string]*compiledPolicy, len(input))
	for _, policy := range input {
		if policy.Name == "" {
			return nil, errors.New("policy name is required")
		}
		if _, exists := result[policy.Name]; exists {
			return nil, fmt.Errorf("duplicate policy name %q", policy.Name)
		}
		if existing, ok := prev[policy.Name]; ok && reflect.DeepEqual(existing.definition, policy) {
			result[policy.Name] = existing
			continue
		}
		compiled, err := compilePolicy(policy)
		if err != nil {
			return nil, fmt.Errorf("policy %q: %w", policy.Name, err)
		}
		result[policy.Name] = compiled
	}
	return result, nil
}

func compilePolicy(policy Policy) (*compiledPolicy, error) {
	compiled := &compiledPolicy{definition: policy}
	if config := policy.Request; config != nil {
		if config.MaxBodyBytes < 0 || config.Timeout < 0 {
			return nil, errors.New("request limits cannot be negative")
		}
		if config.MaxBodyBytes == 0 && config.Timeout == 0 {
			return nil, errors.New("request policy sets no limit")
		}
		if config.Timeout > 0 {
			compiled.middleware = append(compiled.middleware, timeoutMiddleware(time.Duration(config.Timeout)))
		}
		if config.MaxBodyBytes > 0 {
			compiled.middleware = append(compiled.middleware, bodyLimitMiddleware(policy.Name, config.MaxBodyBytes))
		}
	}
	if config := policy.RateLimit; config != nil {
		limiter, err := newRateLimiter(policy.Name, *config)
		if err != nil {
			return nil, err
		}
		compiled.middleware = append(compiled.middleware, limiter.middleware)
	}
	if config := policy.Concurrency; config != nil {
		if config.Max <= 0 {
			return nil, errors.New("concurrency max must be positive")
		}
		compiled.middleware = append(compiled.middleware, concurrencyMiddleware(policy.Name, config.Max))
	}
	if len(compiled.middleware) == 0 {
		return nil, errors.New("policy has no limits")
	}
	return compiled, nil
}

// wrap applies the policy to next unless an outer scope already applied it
// to this request.
func (p *compiledPolicy) wrap(next http.Handler) http.Handler {
	wrapped := Chain(next, p.middleware...)
	name := p.definition.Name
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if state := requestStateFrom(r.Context()); state != nil {
			if !state.markApplied(name) {
				next.ServeHTTP(w, r)
				return
			}
		}
		wrapped.ServeHTTP(w, r)
	})
}

func applyPolicies(handler http.Handler, names []string, policies map[string]*compiledPolicy) (http.Handler, error) {
	for i := len(names) - 1; i >= 0; i-- {
		policy, ok := policies[names[i]]
		if !ok {
			return nil, fmt.Errorf("unknown policy %q", names[i])
		}
		handler = policy.wrap(handler)
	}
	return handler, nil
}

// timeoutMiddleware bounds a request through its context. Unlike
// http.TimeoutHandler it does not buffer the response, so streaming,
// WebSockets and large downloads pass through untouched.
func timeoutMiddleware(timeout time.Duration) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func bodyLimitMiddleware(policy string, limit int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > limit {
				reject(w, r, policy+":body", http.StatusRequestEntityTooLarge, "request body too large")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			next.ServeHTTP(w, r)
		})
	}
}

func concurrencyMiddleware(policy string, limit int) Middleware {
	slots := make(chan struct{}, limit)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
				next.ServeHTTP(w, r)
			default:
				w.Header().Set("Retry-After", "1")
				reject(w, r, policy+":concurrency", http.StatusServiceUnavailable, "too many concurrent requests")
			}
		})
	}
}

// rateLimiter is a token bucket per client, or one shared bucket. Clients
// are kept in LRU order so that idle entries expire in O(1) and a full table
// evicts the least recently seen client instead of rejecting new ones.
type rateLimiter struct {
	name       string
	limit      rate.Limit
	burst      int
	retryAfter string
	global     *rate.Limiter

	maxKeys     int
	idleTimeout time.Duration
	mu          sync.Mutex
	clients     map[string]*list.Element
	recent      *list.List // of *rateClient, most recent first
}

type rateClient struct {
	key     string
	limiter *rate.Limiter
	seen    time.Time
}

func newRateLimiter(name string, config RateLimitPolicy) (*rateLimiter, error) {
	if config.RequestsPerSecond <= 0 || config.Burst <= 0 {
		return nil, errors.New("rate limit requests_per_second and burst must be positive")
	}
	if config.MaxKeys < 0 || config.IdleTimeout < 0 {
		return nil, errors.New("rate limit max_keys and idle_timeout cannot be negative")
	}
	limiter := &rateLimiter{
		name:        name,
		limit:       rate.Limit(config.RequestsPerSecond),
		burst:       config.Burst,
		retryAfter:  strconv.Itoa(max(1, int(math.Ceil(1/config.RequestsPerSecond)))),
		maxKeys:     config.MaxKeys,
		idleTimeout: durationOr(config.IdleTimeout, defaultRateLimitIdleTimeout),
	}
	if limiter.maxKeys == 0 {
		limiter.maxKeys = defaultRateLimitMaxKeys
	}
	switch strings.ToLower(strings.TrimSpace(config.Key)) {
	case "", "client_ip":
		limiter.clients = make(map[string]*list.Element)
		limiter.recent = list.New()
	case "global":
		limiter.global = rate.NewLimiter(limiter.limit, limiter.burst)
	default:
		return nil, fmt.Errorf("unsupported rate limit key %q", config.Key)
	}
	return limiter, nil
}

func (l *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(r, time.Now()) {
			w.Header().Set("Retry-After", l.retryAfter)
			reject(w, r, l.name+":rate", http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (l *rateLimiter) allow(r *http.Request, now time.Time) bool {
	if l.global != nil {
		return l.global.AllowN(now, 1)
	}
	key := rateLimitKey(r)

	l.mu.Lock()
	defer l.mu.Unlock()
	for oldest := l.recent.Back(); oldest != nil; oldest = l.recent.Back() {
		client := oldest.Value.(*rateClient)
		if now.Sub(client.seen) < l.idleTimeout {
			break
		}
		l.remove(oldest)
	}
	var client *rateClient
	if element, ok := l.clients[key]; ok {
		client = element.Value.(*rateClient)
		l.recent.MoveToFront(element)
	} else {
		if l.recent.Len() >= l.maxKeys {
			l.remove(l.recent.Back())
		}
		client = &rateClient{key: key, limiter: rate.NewLimiter(l.limit, l.burst)}
		l.clients[key] = l.recent.PushFront(client)
	}
	client.seen = now
	return client.limiter.AllowN(now, 1)
}

func (l *rateLimiter) remove(element *list.Element) {
	l.recent.Remove(element)
	delete(l.clients, element.Value.(*rateClient).key)
}

// rateLimitKey groups IPv6 clients by /64, the smallest block a single
// subscriber is usually assigned, so one client cannot rotate addresses to
// escape the limit.
func rateLimitKey(r *http.Request) string {
	state := requestStateFrom(r.Context())
	if state == nil || !state.clientIP.IsValid() {
		return "unknown"
	}
	address := state.clientIP
	if address.Is6() {
		prefix, _ := address.Prefix(64)
		return prefix.String()
	}
	return address.String()
}
