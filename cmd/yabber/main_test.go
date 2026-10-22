package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/lsongdev/yabber"
)

func TestPathsResolve(t *testing.T) {
	for _, test := range []struct{ dir, config, wantDir, wantConfig string }{
		{"", "", ".", "config.yaml"},
		{"/var/lib/yabber", "", "/var/lib/yabber", "/var/lib/yabber/config.yaml"},
		{"", "/etc/yabber/config.yaml", "/etc/yabber", "/etc/yabber/config.yaml"},
		{"/var/lib/yabber", "/etc/yabber/site.yaml", "/var/lib/yabber", "/etc/yabber/site.yaml"},
	} {
		p := paths{dir: test.dir, config: test.config}
		p.resolve()
		if p.dir != test.wantDir || p.config != test.wantConfig {
			t.Errorf("resolve(%q, %q) = (%q, %q)", test.dir, test.config, p.dir, p.config)
		}
	}
}

func TestPidFileLocksTheDataDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no locking on Windows")
	}
	path := filepath.Join(t.TempDir(), "yabber.pid")
	if _, err := runningPid(path); err == nil {
		t.Fatal("reload target found before any instance started")
	}
	lock, err := acquirePidFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquirePidFile(path); err == nil || !strings.Contains(err.Error(), "another yabber") {
		t.Fatalf("second instance: %v", err)
	}
	if pid, err := runningPid(path); err != nil || pid != os.Getpid() {
		t.Fatalf("runningPid = %d, %v", pid, err)
	}
	lock.release()

	// A pid file left behind by a crash is not mistaken for a running instance.
	os.WriteFile(path, []byte("12345\n"), 0o644)
	if _, err := runningPid(path); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale pid file: %v", err)
	}
}

// signedRelease serves SHA256SUMS signed by key, plus the given files.
func signedRelease(t *testing.T, key ed25519.PrivateKey, files map[string][]byte) *httptest.Server {
	t.Helper()
	var sums strings.Builder
	for name, data := range files {
		sum := sha256.Sum256(data)
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(sum[:]), name)
	}
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(sums.String())))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch name := strings.TrimPrefix(r.URL.Path, "/release/"); name {
		case "SHA256SUMS":
			w.Write([]byte(sums.String()))
		case "SHA256SUMS.sig":
			w.Write([]byte(signature + "\n"))
		default:
			data, ok := files[name]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Write(data)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestUpdateRequiresSignedChecksums(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	_, other, _ := ed25519.GenerateKey(nil)
	binary := []byte("#!/bin/sh\necho yabber test\n")
	asset := assetName()
	ctx := context.Background()

	server := signedRelease(t, private, map[string][]byte{asset: binary})
	sums, err := verifiedChecksums(ctx, server.URL+"/release", public)
	if err != nil {
		t.Fatal(err)
	}
	want := sums[asset]
	dir := t.TempDir()
	staged, err := download(ctx, server.URL+"/release/"+asset, dir, want)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := fileSHA256(staged); got != want {
		t.Fatalf("staged checksum = %s", got)
	}
	if _, err := download(ctx, server.URL+"/release/"+asset, dir, strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("tampered download: %v", err)
	}

	// A mirror signing with any other key is refused.
	forged := signedRelease(t, other, map[string][]byte{asset: []byte("evil")})
	if _, err := verifiedChecksums(ctx, forged.URL+"/release", public); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("forged release: %v", err)
	}
	// So is a release without a signature.
	unsigned := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("0000  " + asset + "\n"))
	}))
	defer unsigned.Close()
	if _, err := verifiedChecksums(ctx, unsigned.URL, public); err == nil {
		t.Fatal("unsigned release accepted")
	}
}

func TestReleaseBase(t *testing.T) {
	for _, test := range []struct{ mirror, tag, want string }{
		{"", "", releasesURL + "/latest/download"},
		{"", "2026.10.22", releasesURL + "/download/2026.10.22"},
		{"https://mirror.example/yabber/latest/", "", "https://mirror.example/yabber/latest"},
	} {
		if got, err := releaseBase(test.mirror, test.tag); err != nil || got != test.want {
			t.Errorf("releaseBase(%q, %q) = %q, %v", test.mirror, test.tag, got, err)
		}
	}
	if _, err := releaseBase("https://mirror.example", "2026.10.22"); err == nil {
		t.Error("-version with -mirror accepted")
	}
	if len(releasePublicKey) != ed25519.PublicKeySize {
		t.Error("embedded release key is invalid")
	}
}

func TestSaverRoundTripsAndKeepsBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	original := "# hand-written\nsites:\n  - hosts: [a.com]\n    respond: a\n"
	os.WriteFile(path, []byte(original), 0o640)
	config, err := yabber.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	config.Sites = append(config.Sites, yabber.Site{Hosts: []string{"b.com"}, Handler: yabber.Handler{
		Proxy:      &yabber.Proxy{Upstream: "http://127.0.0.1:3000", DialTimeout: yabber.Duration(2e9)},
		Extensions: map[string]any{"worker": "export default {}"},
	}})
	if err := saver(path)(config); err != nil {
		t.Fatal(err)
	}
	reloaded, err := yabber.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reloaded, config) {
		data, _ := os.ReadFile(path)
		t.Fatalf("round trip differs:\n%s", data)
	}
	if backup, _ := os.ReadFile(path + ".bak"); string(backup) != original {
		t.Fatalf("backup = %q", backup)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v", info.Mode())
	}
}

func TestAdminTokenIsGeneratedOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.token")
	first, err := adminToken(path)
	if err != nil || len(first) < 20 {
		t.Fatalf("token = %q, %v", first, err)
	}
	second, _ := adminToken(path)
	if second != first {
		t.Fatal("token changed between runs")
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode())
	}
}
