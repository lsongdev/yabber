package yabber

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestParseShorthands(t *testing.T) {
	config, err := Parse([]byte(`
sites:
  - hosts: [app.example.com]
    proxy: http://127.0.0.1:3000
  - hosts: [example.com]
    routes:
      - path: /static/
        files: /srv/www
      - path: /old/
        redirect: https://example.org/
      - path: /api/
        proxy:
          upstream: unix:/run/app.sock
          strip_prefix: /api
          dial_timeout: 2s
      - path: /
        respond: hello
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := config.Sites[0].Proxy.Upstream; got != "http://127.0.0.1:3000" {
		t.Fatalf("site proxy upstream = %q", got)
	}
	routes := config.Sites[1].Routes
	if routes[0].Files.Root != "/srv/www" || routes[1].Redirect.To != "https://example.org/" || routes[3].Respond.Body != "hello" {
		t.Fatalf("routes = %#v", routes)
	}
	if proxy := routes[2].Proxy; proxy.Upstream != "unix:/run/app.sock" || proxy.DialTimeout != Duration(2*time.Second) {
		t.Fatalf("proxy = %#v", proxy)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	for name, input := range map[string]string{
		"top level":    "sites: []\nlisteners_: []\n",
		"nested":       "sites:\n  - hosts: [a.com]\n    proxy: {upstream: http://x, bogus: 1}\n",
		"bad duration": "server: {idle_timeout: soon}\nsites: []\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
}

func TestUnknownSiteKeyIsReportedAtCompile(t *testing.T) {
	config, err := Parse([]byte("sites:\n  - hosts: [a.com]\n    polices: [x]\n    respond: ok\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(config); err == nil || !strings.Contains(err.Error(), `unknown field or handler "polices"`) {
		t.Fatalf("error = %v", err)
	}
}

func TestJSONAndYAMLRoundTrip(t *testing.T) {
	original := Config{
		Server: ServerConfig{IdleTimeout: Duration(time.Minute)},
		Sites: []Site{{
			Hosts: []string{"example.com"},
			Routes: []Route{
				{Path: "/api/", Handler: Handler{Proxy: &Proxy{Upstream: "http://127.0.0.1:1", DialTimeout: Duration(time.Second)}}},
				{Path: "/", Handler: Handler{Extensions: map[string]any{"worker": map[string]any{"script": "x"}}}},
			},
		}},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"idle_timeout":"1m0s"`) || !strings.Contains(string(data), `"worker":{"script":"x"}`) {
		t.Fatalf("json = %s", data)
	}
	var fromJSON Config
	if err := json.Unmarshal(data, &fromJSON); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromJSON, original) {
		t.Fatalf("JSON round trip:\n got %#v\nwant %#v", fromJSON, original)
	}

	data, err = yaml.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	fromYAML, err := Parse(data)
	if err != nil {
		t.Fatalf("%v\n%s", err, data)
	}
	if !reflect.DeepEqual(fromYAML, original) {
		t.Fatalf("YAML round trip:\n got %#v\nwant %#v\n%s", fromYAML, original, data)
	}

	if err := json.Unmarshal([]byte(`{"sites":[{"hosts":["a"],"proxy":{"upstream":"x","bogus":1}}]}`), &fromJSON); err == nil {
		t.Fatal("JSON decoding accepted an unknown nested field")
	}
}

func TestCloneIsDeep(t *testing.T) {
	original := Config{Sites: []Site{{Hosts: []string{"a.com"}, Handler: Handler{
		Proxy:      &Proxy{Upstream: "http://a"},
		Extensions: map[string]any{"x": map[string]any{"k": "v"}},
	}}}}
	clone := original.Clone()
	clone.Sites[0].Hosts[0] = "b.com"
	clone.Sites[0].Proxy.Upstream = "http://b"
	clone.Sites[0].Extensions["x"].(map[string]any)["k"] = "changed"
	if original.Sites[0].Hosts[0] != "a.com" || original.Sites[0].Proxy.Upstream != "http://a" ||
		original.Sites[0].Extensions["x"].(map[string]any)["k"] != "v" {
		t.Fatalf("clone shares memory with original: %#v", original)
	}
}

func TestLoadResolvesRelativePaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "yabber.yaml")
	data := "tls:\n  certificates:\n    - {cert: certs/a.pem, key: certs/a.key}\nsites:\n  - hosts: [a.com]\n    files: public\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	config, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := config.TLS.Certificates[0].Cert; got != filepath.Join(dir, "certs/a.pem") {
		t.Fatalf("cert = %q", got)
	}
	if got := config.Sites[0].Files.Root; got != filepath.Join(dir, "public") {
		t.Fatalf("files root = %q", got)
	}
}

func TestExampleConfiguration(t *testing.T) {
	config, err := Load("config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Sites) == 0 || len(config.Policies) == 0 {
		t.Fatalf("example config = %#v", config)
	}
}
