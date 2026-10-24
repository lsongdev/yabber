package web

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/lsongdev/yabber"
	"github.com/lsongdev/yabber/api"
)

func TestManifestFollowsContract(t *testing.T) {
	data, err := fs.ReadFile(UI, "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Contract int
		ID       string
		Title    string
		Entry    string
		Styles   []string
		Nav      []struct{ Path string }
	}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m.Contract != 1 || m.ID != "yabber" || m.Title == "" {
		t.Fatalf("manifest = %+v", m)
	}
	for _, name := range append([]string{m.Entry, "index.html"}, m.Styles...) {
		if _, err := fs.Stat(UI, name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	entry, _ := fs.ReadFile(UI, m.Entry)
	if !regexp.MustCompile(`export (function|const) mount\b`).Match(entry) {
		t.Error("entry does not export mount")
	}
	for _, n := range m.Nav {
		if !strings.Contains(string(entry), `path: '`+n.Path+`'`) {
			t.Errorf("no route for %s", n.Path)
		}
	}
}

func TestStandaloneAuthenticatesWithToken(t *testing.T) {
	server, err := yabber.New(yabber.Config{Listeners: []yabber.Listener{{Name: "http", Address: "127.0.0.1:0"}}})
	if err != nil {
		t.Fatal(err)
	}
	management, _ := api.New(server, api.Options{})
	h := New(management).Standalone("tok")
	for name, tc := range map[string]struct {
		set  func(*http.Request)
		want int
	}{
		"anonymous":    {func(*http.Request) {}, 401},
		"bearer":       {func(r *http.Request) { r.Header.Set("Authorization", "Bearer tok") }, 200},
		"wrong bearer": {func(r *http.Request) { r.Header.Set("Authorization", "Bearer nope") }, 401},
		"basic":        {func(r *http.Request) { r.SetBasicAuth("anyone", "tok") }, 200},
	} {
		req := httptest.NewRequest("GET", "/api/status", nil)
		tc.set(req)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Errorf("%s: %d, want %d", name, w.Code, tc.want)
		}
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("", "tok")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatalf("index: %d", w.Code)
	}
}
