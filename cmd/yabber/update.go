package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

var releasesURL = "https://api.github.com/repos/lsongdev/yabber/releases"

type release struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// updateCommand replaces the running binary with a release build for the
// same platform. Several builds can share a date tag, so whether an update
// is needed is decided by the binary's SHA-256, not the version string.
func updateCommand(args []string) error {
	flags := flag.NewFlagSet("update", flag.ExitOnError)
	check := flags.Bool("check", false, "only report whether an update is available")
	tag := flags.String("version", "", "release to install (default: latest)")
	flags.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	executable, err := os.Executable()
	if err == nil {
		executable, err = filepath.EvalSymlinks(executable)
	}
	if err != nil {
		return err
	}
	asset := assetName()
	rel, err := fetchRelease(ctx, *tag)
	if err != nil {
		return err
	}
	binaryURL, sumsURL := rel.asset(asset), rel.asset("SHA256SUMS")
	if binaryURL == "" || sumsURL == "" {
		return fmt.Errorf("release %s has no %s or SHA256SUMS", rel.TagName, asset)
	}
	want, err := releaseChecksum(ctx, sumsURL, asset)
	if err != nil {
		return err
	}
	if current, err := fileSHA256(executable); err == nil && current == want {
		fmt.Printf("already up to date: %s (%s)\n", rel.TagName, asset)
		return nil
	}
	if *check {
		fmt.Printf("update available: %s -> %s (%s)\n", version, rel.TagName, asset)
		return nil
	}

	staged, err := download(ctx, binaryURL, filepath.Dir(executable), want)
	if err != nil {
		return err
	}
	defer os.Remove(staged)
	// Smoke test before replacing anything: the new binary must start here.
	out, err := exec.CommandContext(ctx, staged, "version").CombinedOutput()
	if err != nil || !strings.HasPrefix(string(out), "yabber ") {
		return fmt.Errorf("downloaded %s failed `version` (%v): %s", rel.TagName, err, strings.TrimSpace(string(out)))
	}
	if err := replaceExecutable(staged, executable); err != nil {
		return err
	}
	fmt.Printf("updated %s: %s -> %s", executable, version, out)
	fmt.Println(restartHint())
	return nil
}

// assetName is the release file built for this platform, matching the
// Makefile's naming, including the ARM and MIPS variant of this binary.
func assetName() string {
	name := "yabber_" + runtime.GOOS + "_" + runtime.GOARCH
	switch runtime.GOARCH {
	case "arm":
		name += "_v" + buildSetting("GOARM", "7")
	case "mips", "mipsle":
		name += "_" + buildSetting("GOMIPS", "softfloat")
	}
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

func buildSetting(key, fallback string) string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == key && setting.Value != "" {
				return setting.Value
			}
		}
	}
	return fallback
}

func fetchRelease(ctx context.Context, tag string) (*release, error) {
	url := releasesURL + "/latest"
	if tag != "" {
		url = releasesURL + "/tags/" + tag
	}
	body, err := get(ctx, url)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	var rel release
	if err := json.NewDecoder(body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decode release: %w", err)
	}
	return &rel, nil
}

func (r *release) asset(name string) string {
	for _, asset := range r.Assets {
		if asset.Name == name {
			return asset.URL
		}
	}
	return ""
}

func releaseChecksum(ctx context.Context, url, asset string) (string, error) {
	body, err := get(ctx, url)
	if err != nil {
		return "", err
	}
	defer body.Close()
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		if sum, name, ok := strings.Cut(scanner.Text(), "  "); ok && name == asset {
			return sum, nil
		}
	}
	return "", fmt.Errorf("SHA256SUMS has no entry for %s", asset)
}

// download saves url into dir, verifying its SHA-256, and returns the path.
// Staging in the executable's directory keeps the final rename atomic.
func download(ctx context.Context, url, dir, wantSHA256 string) (string, error) {
	body, err := get(ctx, url)
	if err != nil {
		return "", err
	}
	defer body.Close()
	file, err := os.CreateTemp(dir, ".yabber-update-*")
	if err != nil {
		return "", fmt.Errorf("stage update next to the binary: %w", err)
	}
	hash := sha256.New()
	_, err = io.Copy(io.MultiWriter(file, hash), body)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		if got := hex.EncodeToString(hash.Sum(nil)); got != wantSHA256 {
			err = fmt.Errorf("checksum mismatch: got %s, want %s", got, wantSHA256)
		}
	}
	if err == nil {
		err = os.Chmod(file.Name(), 0o755)
	}
	if err != nil {
		os.Remove(file.Name())
		return "", err
	}
	return file.Name(), nil
}

func replaceExecutable(staged, executable string) error {
	if runtime.GOOS == "windows" {
		// A running executable cannot be replaced, but it can be renamed.
		old := executable + ".old"
		os.Remove(old)
		if err := os.Rename(executable, old); err != nil {
			return err
		}
	}
	return os.Rename(staged, executable)
}

func get(ctx context.Context, url string) (io.ReadCloser, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "yabber-update")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", url, response.Status)
	}
	return response.Body, nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func restartHint() string {
	switch {
	case exists("/etc/openwrt_release"):
		return "restart it with: /etc/init.d/yabber restart"
	case exists("/run/systemd/system"):
		return "restart it with: systemctl restart yabber"
	default:
		return "restart yabber to use the new version"
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, os.ErrNotExist)
}
