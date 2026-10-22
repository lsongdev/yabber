// Package web serves yabber's management panel: static ES modules built on
// Preact and htm, embedded in the binary, with no build step. The panel
// talks to the management API (package api) in the same origin, using the
// token the user enters.
package web

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"io/fs"
	"net/http"
	"regexp"
)

//go:embed static
var static embed.FS

var importMap = regexp.MustCompile(`(?s)<script type="importmap">(.*?)</script>`)

// contentSecurityPolicy allows only the panel's own files and API calls: no
// third-party origins, no framing, and no inline script except index.html's
// import map, which is allowed by its hash so that editing it needs no
// other change.
func contentSecurityPolicy(index []byte) string {
	scripts := "'self'"
	if match := importMap.FindSubmatch(index); match != nil {
		sum := sha256.Sum256(match[1])
		scripts += " 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}
	return "default-src 'none'; script-src " + scripts + "; style-src 'self'; img-src 'self' data:; " +
		"connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
}

// Handler serves the panel.
func Handler() http.Handler {
	files, _ := fs.Sub(static, "static")
	index, _ := fs.ReadFile(files, "index.html")
	policy := contentSecurityPolicy(index)
	server := http.FileServerFS(files)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("Content-Security-Policy", policy)
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("Referrer-Policy", "no-referrer")
		// Embedded files carry no modification time; revalidate on each load
		// so an upgraded binary never serves a stale module.
		header.Set("Cache-Control", "no-cache")
		server.ServeHTTP(w, r)
	})
}
