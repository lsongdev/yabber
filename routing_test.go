package yabber

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostAndRouteMatching(t *testing.T) {
	server := newServer(t, Config{
		Listeners: []Listener{{Name: "http", Address: ":8080"}},
		Sites: []Site{
			{Hosts: []string{"api.example.com"}, Routes: []Route{
				{Method: "GET", Path: "/health", Handler: Handler{Respond: &Respond{Status: 201, Body: "healthy"}}},
			}},
			{Hosts: []string{"*.example.net"}, Handler: respond("wildcard")},
			{Hosts: []string{"*"}, Handler: respond("fallback")},
		},
	})
	tests := []struct {
		name, method, url string
		status            int
		body              string
	}{
		{"exact host", "GET", "http://api.example.com/health", 201, "healthy"},
		{"port and case ignored", "GET", "http://API.example.com.:8080/health", 201, "healthy"},
		{"method mismatch", "POST", "http://api.example.com/health", http.StatusMethodNotAllowed, ""},
		{"single label wildcard", "GET", "http://one.example.net/", 200, "wildcard"},
		{"wildcard does not cross labels", "GET", "http://one.two.example.net/", 200, "fallback"},
		{"catch-all", "GET", "http://unknown.example.org/", 200, "fallback"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := serve(t, server, "http", httptest.NewRequest(test.method, test.url, nil))
			assertResponse(t, response, test.status, test.body)
		})
	}
}

func TestUnknownHostIsNotFound(t *testing.T) {
	server := newServer(t, siteConfig(Site{Hosts: []string{"example.com"}, Handler: respond("ok")}))
	assertResponse(t, get(t, server, "http://other.com/"), http.StatusNotFound, "")
}

func TestSiteValidation(t *testing.T) {
	tests := map[string]struct {
		site Site
		want string
	}{
		"no hosts":            {Site{Handler: respond("x")}, "at least one host"},
		"invalid host":        {Site{Hosts: []string{"a.com:80"}, Handler: respond("x")}, "invalid host"},
		"routes and handler":  {Site{Hosts: []string{"a.com"}, Handler: respond("x"), Routes: []Route{{Handler: respond("y")}}}, "not both"},
		"two handlers":        {Site{Hosts: []string{"a.com"}, Handler: Handler{Respond: &Respond{}, Redirect: &Redirect{To: "/"}}}, "exactly one handler"},
		"conflicting routes":  {Site{Hosts: []string{"a.com"}, Routes: []Route{{Name: "a", Handler: respond("x")}, {Name: "b", Handler: respond("y")}}}, "conflicts"},
		"unknown listener":    {Site{Hosts: []string{"a.com"}, Listeners: []string{"nope"}, Handler: respond("x")}, "unknown listener"},
		"unknown extension":   {Site{Hosts: []string{"a.com"}, Handler: Handler{Extensions: map[string]any{"worker": "x"}}}, `unknown field or handler "worker"`},
		"invalid status":      {Site{Hosts: []string{"a.com"}, Handler: Handler{Respond: &Respond{Status: 700}}}, "invalid response status"},
		"relative route path": {Site{Hosts: []string{"a.com"}, Routes: []Route{{Path: "api", Handler: respond("x")}}}, "must start with /"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := Validate(siteConfig(test.site))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDuplicateHostAcrossSites(t *testing.T) {
	config := siteConfig(Site{Name: "one", Hosts: []string{"a.com"}, Handler: respond("1")})
	config.Sites = append(config.Sites, Site{Name: "two", Hosts: []string{"A.com."}, Handler: respond("2")})
	if err := Validate(config); err == nil || !strings.Contains(err.Error(), `already served by site "one"`) {
		t.Fatalf("error = %v", err)
	}
}

func TestExtensionHandler(t *testing.T) {
	type greeting struct {
		Text string `yaml:"text"`
	}
	option := WithHandler("greet", func(decode func(any) error) (http.Handler, error) {
		var config greeting
		if err := decode(&config); err != nil {
			return nil, err
		}
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(config.Text)) }), nil
	})
	config, err := Parse([]byte("listeners: [{name: http, address: ':0'}]\nsites:\n  - hosts: [a.com]\n    greet: {text: hi}\n"))
	if err != nil {
		t.Fatal(err)
	}
	server := newServer(t, config, option)
	assertResponse(t, get(t, server, "http://a.com/"), 200, "hi")

	config.Sites[0].Extensions["greet"] = map[string]any{"txt": "typo"}
	if err := Validate(config, option); err == nil || !strings.Contains(err.Error(), "txt") {
		t.Fatalf("error = %v", err)
	}
}

func TestRedirectHandler(t *testing.T) {
	server := newServer(t, siteConfig(Site{Hosts: []string{"old.com"}, Handler: Handler{
		Redirect: &Redirect{To: "https://new.com/", Status: 301, PreservePath: true},
	}}))
	response := get(t, server, "http://old.com/a/b?c=d")
	if response.Code != 301 || response.Header().Get("Location") != "https://new.com/a/b?c=d" {
		t.Fatalf("response = %d %q", response.Code, response.Header().Get("Location"))
	}
}

func TestFilesHideDotfilesAndListings(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{
		"index.html":                 "home",
		".env":                       "secret",
		".git/config":                "secret",
		"empty/.keep":                "",
		"docs/index.html":            "docs",
		".well-known/security.txt":   "contact",
		"assets/app.js":              "js",
		"assets/nested/readme.txt":   "nested",
		"browse-me/file.txt":         "f",
		"public/.hidden/inside.html": "secret",
	} {
		path := filepath.Join(root, name)
		os.MkdirAll(filepath.Dir(path), 0o755)
		os.WriteFile(path, []byte(content), 0o644)
	}
	server := newServer(t, siteConfig(Site{Hosts: []string{"a.com"}, Handler: Handler{Files: &Files{Root: root}}}))
	for path, status := range map[string]int{
		"/":                           200,
		"/docs/":                      200,
		"/assets/app.js":              200,
		"/.well-known/security.txt":   200,
		"/.env":                       404,
		"/.git/config":                404,
		"/public/.hidden/inside.html": 404,
		"/assets/":                    404,
	} {
		if response := get(t, server, "http://a.com"+path); response.Code != status {
			t.Errorf("GET %s = %d, want %d", path, response.Code, status)
		}
	}
}

func TestFilesStripPrefix(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "app.js"), []byte("js"), 0o644)
	server := newServer(t, siteConfig(Site{Hosts: []string{"a.com"}, Routes: []Route{
		{Path: "/static/", Handler: Handler{Files: &Files{Root: root, StripPrefix: "/static"}}},
	}}))
	assertResponse(t, get(t, server, "http://a.com/static/app.js"), 200, "js")
}

func TestFilesRootMustExist(t *testing.T) {
	err := Validate(siteConfig(Site{Hosts: []string{"a.com"}, Handler: Handler{Files: &Files{Root: "/does/not/exist"}}}))
	if err == nil || !strings.Contains(err.Error(), "files root") {
		t.Fatalf("error = %v", err)
	}
}
