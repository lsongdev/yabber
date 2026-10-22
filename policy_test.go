package yabber

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func policyConfig(policy Policy) Config {
	config := siteConfig(Site{Hosts: []string{"a.com"}, Handler: respond("ok")})
	config.Policies = []Policy{policy}
	config.Sites[0].Policies = []string{policy.Name}
	return config
}

func statusFrom(t *testing.T, server *Server, remoteAddr string) int {
	t.Helper()
	request := httptest.NewRequest("GET", "http://a.com/", nil)
	request.RemoteAddr = remoteAddr
	return serve(t, server, "http", request).Code
}

func TestRateLimitByClient(t *testing.T) {
	server := newServer(t, policyConfig(Policy{Name: "api", RateLimit: &RateLimitPolicy{RequestsPerSecond: 0.001, Burst: 1}}))
	for _, step := range []struct {
		remote string
		status int
	}{
		{"192.0.2.1:1", 200},
		{"192.0.2.1:2", 429},
		{"192.0.2.2:1", 200},
		{"[2001:db8::1]:1", 200},
		{"[2001:db8::2]:1", 429}, // same /64
		{"[2001:db8:0:1::1]:1", 200},
	} {
		if got := statusFrom(t, server, step.remote); got != step.status {
			t.Fatalf("%s: status = %d, want %d", step.remote, got, step.status)
		}
	}
	if rejected := server.Metrics().Total().Rejected; rejected != 2 {
		t.Fatalf("rejected = %d", rejected)
	}
}

func TestRateLimitEvictsInsteadOfLockingOut(t *testing.T) {
	server := newServer(t, policyConfig(Policy{Name: "api", RateLimit: &RateLimitPolicy{RequestsPerSecond: 0.001, Burst: 1, MaxKeys: 2}}))
	for _, remote := range []string{"192.0.2.1:1", "192.0.2.2:1", "192.0.2.3:1"} {
		if got := statusFrom(t, server, remote); got != 200 {
			t.Fatalf("new client %s rejected with %d while the table was full", remote, got)
		}
	}
	if got := statusFrom(t, server, "192.0.2.3:2"); got != 429 {
		t.Fatalf("tracked client status = %d", got)
	}
}

func TestPolicyStateSurvivesApply(t *testing.T) {
	config := policyConfig(Policy{Name: "api", RateLimit: &RateLimitPolicy{RequestsPerSecond: 0.001, Burst: 1}})
	server := newServer(t, config)
	statusFrom(t, server, "192.0.2.1:1")
	config.Sites[0].Handler = respond("changed")
	if err := server.Apply(config); err != nil {
		t.Fatal(err)
	}
	if got := statusFrom(t, server, "192.0.2.1:1"); got != 429 {
		t.Fatalf("status = %d; the bucket was reset by an unrelated change", got)
	}
}

func TestPolicyAppliesOncePerRequest(t *testing.T) {
	config := policyConfig(Policy{Name: "one", Concurrency: &ConcurrencyPolicy{Max: 1}})
	config.Listeners[0].Policies = []string{"one"}
	config.Sites[0].Handler = Handler{}
	config.Sites[0].Routes = []Route{{Policies: []string{"one"}, Handler: respond("ok")}}
	server := newServer(t, config)
	if got := statusFrom(t, server, "192.0.2.1:1"); got != 200 {
		t.Fatalf("status = %d; nested scopes acquired the same slot twice", got)
	}
}

func TestConcurrencyLimit(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	middleware := concurrencyMiddleware("expensive", 1)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
	}))
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
		close(done)
	}()
	<-started
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", response.Code)
	}
	close(release)
	<-done
}

func TestBodyLimit(t *testing.T) {
	// A chunked body is streamed, so the upstream may see the request start,
	// but it must never receive the complete oversized body.
	var received atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if body, err := io.ReadAll(r.Body); err == nil && len(body) > 5 {
			received.Store(true)
		}
	}))
	defer upstream.Close()
	config := policyConfig(Policy{Name: "small", Request: &RequestPolicy{MaxBodyBytes: 5}})
	config.Sites[0].Handler = Handler{Proxy: &Proxy{Upstream: upstream.URL}}
	server := newServer(t, config)

	request := httptest.NewRequest("POST", "http://a.com/", strings.NewReader("123456"))
	assertResponse(t, serve(t, server, "http", request), http.StatusRequestEntityTooLarge, "")
	request = httptest.NewRequest("POST", "http://a.com/", strings.NewReader("123456"))
	request.ContentLength = -1
	assertResponse(t, serve(t, server, "http", request), http.StatusRequestEntityTooLarge, "")
	if received.Load() {
		t.Fatal("oversized body reached the upstream")
	}
}

func TestPolicyValidation(t *testing.T) {
	for name, policy := range map[string]Policy{
		"empty":     {Name: "p"},
		"bad key":   {Name: "p", RateLimit: &RateLimitPolicy{RequestsPerSecond: 1, Burst: 1, Key: "header"}},
		"zero rate": {Name: "p", RateLimit: &RateLimitPolicy{Burst: 1}},
	} {
		if err := Validate(policyConfig(policy)); err == nil {
			t.Errorf("%s: invalid policy accepted", name)
		}
	}
	config := siteConfig(Site{Hosts: []string{"a.com"}, Policies: []string{"missing"}, Handler: respond("x")})
	if err := Validate(config); err == nil || !strings.Contains(err.Error(), `unknown policy "missing"`) {
		t.Fatalf("error = %v", err)
	}
}
