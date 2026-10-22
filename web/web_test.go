package web

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	Handler().ServeHTTP(response, httptest.NewRequest("GET", path, nil))
	return response
}

func TestServesPanelWithSecurityHeaders(t *testing.T) {
	for path, contentType := range map[string]string{
		"/":                              "text/html",
		"/app.js":                        "text/javascript",
		"/vendor/preact/dist/preact.mjs": "text/javascript",
		"/views/sites.js":                "text/javascript",
		"/style.css":                     "text/css",
	} {
		response := get(t, path)
		if response.Code != http.StatusOK || !strings.HasPrefix(response.Header().Get("Content-Type"), contentType) {
			t.Errorf("%s: %d %q", path, response.Code, response.Header().Get("Content-Type"))
		}
		if !strings.Contains(response.Header().Get("Content-Security-Policy"), "script-src 'self'") ||
			response.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: missing security headers %v", path, response.Header())
		}
	}
	if response := get(t, "/missing.js"); response.Code != http.StatusNotFound {
		t.Errorf("missing file: %d", response.Code)
	}
}

// Every import must resolve to an embedded file: relative ones directly,
// bare ones through index.html's import map.
func TestModuleImportsResolve(t *testing.T) {
	files, _ := fs.Sub(static, "static")
	index, _ := fs.ReadFile(files, "index.html")
	match := importMap.FindSubmatch(index)
	if match == nil {
		t.Fatal("index.html has no import map")
	}
	var mapping struct{ Imports map[string]string }
	if err := json.Unmarshal(match[1], &mapping); err != nil {
		t.Fatalf("import map: %v", err)
	}
	for specifier, target := range mapping.Imports {
		if _, err := fs.Stat(files, pathJoin("index.html", target)); err != nil {
			t.Errorf("import map entry %q points to missing %s", specifier, target)
		}
	}
	importPattern := regexp.MustCompile(`(?:from|import)\s*["']([^"']+)["']`)
	fs.WalkDir(files, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !(strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".mjs")) {
			return err
		}
		data, _ := fs.ReadFile(files, path)
		for _, found := range importPattern.FindAllStringSubmatch(string(data), -1) {
			specifier := found[1]
			if !strings.HasPrefix(specifier, "./") && !strings.HasPrefix(specifier, "../") {
				if _, ok := mapping.Imports[specifier]; !ok {
					t.Errorf("%s imports %q, which the import map does not define", path, specifier)
				}
				continue
			}
			if _, err := fs.Stat(files, pathJoin(path, specifier)); err != nil {
				t.Errorf("%s imports %q, which is not embedded", path, specifier)
			}
		}
		return nil
	})
}

func TestPolicyAllowsExactlyTheImportMap(t *testing.T) {
	index := []byte("<script type=\"importmap\">{\"imports\":{}}</script>")
	sum := sha256.Sum256([]byte(`{"imports":{}}`))
	want := "script-src 'self' 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "';"
	if policy := contentSecurityPolicy(index); !strings.Contains(policy, want) {
		t.Fatalf("policy = %s", policy)
	}
	if response := get(t, "/"); !strings.Contains(response.Header().Get("Content-Security-Policy"), "'sha256-") {
		t.Fatalf("served policy lacks the import map hash: %s", response.Header().Get("Content-Security-Policy"))
	}
}

func pathJoin(from, specifier string) string {
	parts := strings.Split(from, "/")
	parts = parts[:len(parts)-1]
	for _, part := range strings.Split(specifier, "/") {
		switch part {
		case ".":
		case "..":
			parts = parts[:len(parts)-1]
		default:
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, "/")
}
