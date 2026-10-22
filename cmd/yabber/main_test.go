package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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

func TestUpdateVerifiesChecksums(t *testing.T) {
	binary := []byte("#!/bin/sh\necho yabber test\n")
	sum := sha256.Sum256(binary)
	asset := assetName()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/releases/latest":
			fmt.Fprintf(w, `{"tag_name":"2026.10.22","assets":[{"name":%q,"browser_download_url":"%[2]s/bin"},{"name":"SHA256SUMS","browser_download_url":"%[2]s/sums"}]}`,
				asset, "http://"+r.Host)
		case "/sums":
			fmt.Fprintf(w, "%s  %s\n%s  other\n", hex.EncodeToString(sum[:]), asset, strings.Repeat("0", 64))
		case "/bin":
			w.Write(binary)
		}
	}))
	defer server.Close()
	releasesURL = server.URL + "/releases"
	ctx := context.Background()

	rel, err := fetchRelease(ctx, "")
	if err != nil || rel.TagName != "2026.10.22" {
		t.Fatalf("release = %#v, %v", rel, err)
	}
	want, err := releaseChecksum(ctx, rel.asset("SHA256SUMS"), asset)
	if err != nil || want != hex.EncodeToString(sum[:]) {
		t.Fatalf("checksum = %q, %v", want, err)
	}
	dir := t.TempDir()
	staged, err := download(ctx, rel.asset(asset), dir, want)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := fileSHA256(staged); got != want {
		t.Fatalf("staged checksum = %s", got)
	}
	if _, err := download(ctx, rel.asset(asset), dir, strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("tampered download: %v", err)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, ".yabber-update-*")); len(leftovers) != 1 {
		t.Fatalf("files after a rejected download = %v, want only the first staged one", leftovers)
	}
}
