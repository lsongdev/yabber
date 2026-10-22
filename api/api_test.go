package api_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/lsongdev/yabber"
	"github.com/lsongdev/yabber/api"
)

const token = "secret-token"

type fixture struct {
	t      *testing.T
	server *yabber.Server
	api    *api.API
	saved  []yabber.Config
	saveMu sync.Mutex
	fail   error
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	server, err := yabber.New(yabber.Config{
		Listeners: []yabber.Listener{{Name: "http", Address: "127.0.0.1:0"}},
		Sites: []yabber.Site{{Hosts: []string{"a.com"},
			Handler: yabber.Handler{Respond: &yabber.Respond{Body: "a"}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, server: server}
	f.api, err = api.New(server, api.Options{Token: token, Save: func(config yabber.Config) error {
		f.saveMu.Lock()
		defer f.saveMu.Unlock()
		if f.fail != nil {
			return f.fail
		}
		f.saved = append(f.saved, config)
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// do sends a request with the token and optional headers given as
// name, value pairs.
func (f *fixture) do(method, path, body string, headers ...string) *httptest.ResponseRecorder {
	f.t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	for i := 0; i+1 < len(headers); i += 2 {
		request.Header.Set(headers[i], headers[i+1])
	}
	response := httptest.NewRecorder()
	f.api.ServeHTTP(response, request)
	return response
}

func (f *fixture) expect(response *httptest.ResponseRecorder, status int) {
	f.t.Helper()
	if response.Code != status {
		f.t.Fatalf("status = %d, want %d: %s", response.Code, status, response.Body.String())
	}
}

// serve sends a request through the gateway itself.
func (f *fixture) serve(host string) string {
	f.t.Helper()
	handler, _ := f.server.Handler("http")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "http://"+host+"/", nil))
	return response.Body.String()
}

func TestAuthentication(t *testing.T) {
	f := newFixture(t)
	for _, header := range []string{"", "Bearer wrong", "Basic " + token, token} {
		request := httptest.NewRequest("GET", "/api/config", nil)
		if header != "" {
			request.Header.Set("Authorization", header)
		}
		response := httptest.NewRecorder()
		f.api.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("Authorization %q: status = %d", header, response.Code)
		}
	}
	unknown := httptest.NewRecorder()
	f.api.ServeHTTP(unknown, httptest.NewRequest("GET", "/api/nope", nil))
	if unknown.Code != http.StatusUnauthorized {
		t.Errorf("unknown endpoint without a token: %d", unknown.Code)
	}
	f.expect(f.do("GET", "/api/nope", ""), http.StatusNotFound)

	for _, open := range []string{"/healthz", "/metrics"} {
		response := httptest.NewRecorder()
		f.api.ServeHTTP(response, httptest.NewRequest("GET", open, nil))
		if response.Code == http.StatusUnauthorized {
			t.Errorf("%s requires a token", open)
		}
	}
	if _, err := api.New(f.server, api.Options{}); err == nil {
		t.Error("New accepted an empty token")
	}
}

func TestReadEndpoints(t *testing.T) {
	f := newFixture(t)
	for _, path := range []string{"/api/status", "/api/config", "/api/sites", "/api/certificates", "/api/events", "/api/metrics"} {
		response := f.do("GET", path, "")
		f.expect(response, http.StatusOK)
		if !json.Valid(response.Body.Bytes()) || response.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%s: not JSON: %s", path, response.Body.String())
		}
	}
	if body := f.do("GET", "/api/certificates", "").Body.String(); strings.TrimSpace(body) != "[]" {
		t.Errorf("empty certificates = %s, want []", body)
	}
}

func TestSiteLifecycle(t *testing.T) {
	f := newFixture(t)
	f.expect(f.do("POST", "/api/sites", `{"hosts":["b.com"],"respond":"b"}`), http.StatusCreated)
	if got := f.serve("b.com"); got != "b" {
		t.Fatalf("new site serves %q", got)
	}
	f.expect(f.do("POST", "/api/sites", `{"hosts":["b.com"],"respond":"again"}`), http.StatusConflict)

	f.expect(f.do("PUT", "/api/sites/b.com", `{"hosts":["b.com","www.b.com"],"respond":"b2"}`), http.StatusOK)
	if got := f.serve("www.b.com"); got != "b2" {
		t.Fatalf("replaced site serves %q", got)
	}
	f.expect(f.do("PUT", "/api/sites/b.com", `{"name":"other","hosts":["b.com"],"respond":"x"}`), http.StatusBadRequest)

	// A body without a name keeps the URL's ID even when its first host changes.
	f.expect(f.do("PUT", "/api/sites/b.com", `{"hosts":["c.com"],"respond":"c"}`), http.StatusOK)
	var site yabber.Site
	json.Unmarshal(f.do("GET", "/api/sites/b.com", "").Body.Bytes(), &site)
	if site.Name != "b.com" || site.Hosts[0] != "c.com" {
		t.Fatalf("site = %#v", site)
	}

	f.expect(f.do("DELETE", "/api/sites/b.com", ""), http.StatusNoContent)
	f.expect(f.do("GET", "/api/sites/b.com", ""), http.StatusNotFound)
	f.expect(f.do("DELETE", "/api/sites/b.com", ""), http.StatusNotFound)
	if got := f.serve("c.com"); got == "c" {
		t.Fatal("deleted site still serves")
	}
	if len(f.saved) != 4 {
		t.Fatalf("saves = %d, want one per successful change", len(f.saved))
	}
	if last := f.saved[len(f.saved)-1]; len(last.Sites) != 1 {
		t.Fatalf("last saved configuration = %#v", last)
	}
}

func TestInvalidChangesAreRejected(t *testing.T) {
	f := newFixture(t)
	for _, test := range []struct {
		body   string
		status int
	}{
		{`{"hosts":["b.com"],"proxy":"ftp://nope"}`, http.StatusUnprocessableEntity},
		{`{"hosts":["a.com"],"name":"dup-host","respond":"x"}`, http.StatusUnprocessableEntity},
		{`{"hosts":["b.com"],"respond":"x","bogus":1}`, http.StatusUnprocessableEntity},
		{`{"hosts":["b.com"],"proxy":{"upstream":"http://x","bogus":1}}`, http.StatusBadRequest},
		{`{"hosts":["b.com"]} {}`, http.StatusBadRequest},
		{`{}`, http.StatusBadRequest},
	} {
		response := f.do("POST", "/api/sites", test.body)
		if response.Code != test.status {
			t.Errorf("%s: status = %d, want %d: %s", test.body, response.Code, test.status, response.Body.String())
		}
	}
	if sites := f.server.Config().Sites; len(sites) != 1 || len(f.saved) != 0 {
		t.Fatalf("a rejected change took effect: sites = %d, saves = %d", len(sites), len(f.saved))
	}
}

func TestIfMatchPreventsLostUpdates(t *testing.T) {
	f := newFixture(t)
	first := f.do("GET", "/api/config", "")
	tag := first.Header().Get("ETag")
	if tag == "" {
		t.Fatal("no ETag")
	}
	var config yabber.Config
	json.Unmarshal(first.Body.Bytes(), &config)

	config.Sites[0].Respond.Body = "edited"
	body, _ := json.Marshal(config)
	updated := f.do("PUT", "/api/config", string(body), "If-Match", tag)
	f.expect(updated, http.StatusOK)
	if updated.Header().Get("ETag") == tag {
		t.Fatal("ETag did not change")
	}

	// A second client still holding the old ETag must not overwrite it.
	config.Sites[0].Respond.Body = "stale"
	body, _ = json.Marshal(config)
	f.expect(f.do("PUT", "/api/config", string(body), "If-Match", tag), http.StatusPreconditionFailed)
	f.expect(f.do("DELETE", "/api/sites/a.com", "", "If-Match", tag), http.StatusPreconditionFailed)
	if got := f.serve("a.com"); got != "edited" {
		t.Fatalf("serves %q", got)
	}
}

func TestSaveFailureIsReported(t *testing.T) {
	f := newFixture(t)
	f.fail = errors.New("disk full")
	response := f.do("POST", "/api/sites", `{"hosts":["b.com"],"respond":"b"}`)
	f.expect(response, http.StatusInternalServerError)
	if !strings.Contains(response.Body.String(), "applied, but saving failed: disk full") {
		t.Fatalf("body = %s", response.Body.String())
	}
}

func TestConcurrentChangesAreSerialized(t *testing.T) {
	f := newFixture(t)
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			body := fmt.Sprintf(`{"hosts":["s%d.com"],"respond":"x"}`, i)
			if response := f.do("POST", "/api/sites", body); response.Code != http.StatusCreated {
				t.Errorf("status = %d", response.Code)
			}
		})
	}
	wg.Wait()
	if sites := f.server.Config().Sites; len(sites) != 21 {
		t.Fatalf("sites = %d, want 21", len(sites))
	}
	last := f.saved[len(f.saved)-1]
	if len(last.Sites) != 21 {
		t.Fatalf("the last save has %d sites; saves ran out of order", len(last.Sites))
	}
}

func TestApplyIsSerializedWithChanges(t *testing.T) {
	f := newFixture(t)
	config := f.server.Config()
	config.Sites[0].Respond.Body = "reloaded"
	if err := f.api.Apply(config); err != nil {
		t.Fatal(err)
	}
	if got := f.serve("a.com"); got != "reloaded" {
		t.Fatalf("serves %q", got)
	}
	if len(f.saved) != 0 {
		t.Fatal("Apply saved the configuration")
	}
}
