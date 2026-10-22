package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

// releaseKey verifies SHA256SUMS.sig. Its private half signs releases in CI
// (tools/sign), so files are checked the same way whether they come from
// GitHub or from a mirror.
const releaseKey = "ZD30+ASsK/qKYEJ6xj2S7qb/sBKa/p6giw4fxjHNVfE="

var (
	releasePublicKey = mustDecodeKey(releaseKey)
	releasesURL      = "https://github.com/lsongdev/yabber/releases"
)

func mustDecodeKey(encoded string) ed25519.PublicKey {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != ed25519.PublicKeySize {
		panic("invalid release key")
	}
	return key
}

// updateCommand replaces the running binary with a release build for the
// same platform, after verifying the release's signed checksums. Several
// builds can share a date tag, so whether an update is needed is decided by
// the binary's SHA-256, not the version string.
func updateCommand(args []string) error {
	flags := flag.NewFlagSet("update", flag.ExitOnError)
	check := flags.Bool("check", false, "only report whether an update is available")
	tag := flags.String("version", "", "release to install (default: latest)")
	mirror := flags.String("mirror", os.Getenv("YABBER_MIRROR"),
		"URL of a directory holding one release's files, instead of GitHub (default $YABBER_MIRROR)")
	flags.Parse(args)

	base, err := releaseBase(*mirror, *tag)
	if err != nil {
		return err
	}
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
	sums, err := verifiedChecksums(ctx, base, releasePublicKey)
	if err != nil {
		return err
	}
	want, ok := sums[asset]
	if !ok {
		return fmt.Errorf("the release has no %s", asset)
	}
	if current, err := fileSHA256(executable); err == nil && current == want {
		fmt.Printf("already up to date (%s)\n", asset)
		return nil
	}
	if *check {
		fmt.Printf("update available: %s from %s\n", asset, base)
		return nil
	}

	staged, err := download(ctx, base+"/"+asset, filepath.Dir(executable), want)
	if err != nil {
		return err
	}
	defer os.Remove(staged)
	// Smoke test before replacing anything: the new binary must start here.
	out, err := exec.CommandContext(ctx, staged, "version").CombinedOutput()
	if err != nil || !strings.HasPrefix(string(out), "yabber ") {
		return fmt.Errorf("the downloaded binary failed `version` (%v): %s", err, strings.TrimSpace(string(out)))
	}
	if err := replaceExecutable(staged, executable); err != nil {
		return err
	}
	fmt.Printf("updated %s: %s -> %s", executable, version, out)
	fmt.Println(restartHint())
	return nil
}

// releaseBase is the URL of the directory holding the release's files.
func releaseBase(mirror, tag string) (string, error) {
	switch {
	case mirror != "" && tag != "":
		return "", errors.New("-version does not apply to a mirror; point -mirror at that release's files")
	case mirror != "":
		return strings.TrimSuffix(mirror, "/"), nil
	case tag != "":
		return releasesURL + "/download/" + tag, nil
	default:
		return releasesURL + "/latest/download", nil
	}
}

// verifiedChecksums fetches SHA256SUMS and its signature from base and
// returns the checksums by file name, refusing them unless key signed them.
func verifiedChecksums(ctx context.Context, base string, key ed25519.PublicKey) (map[string]string, error) {
	sums, err := fetch(ctx, base+"/SHA256SUMS", 1<<20)
	if err != nil {
		return nil, err
	}
	encoded, err := fetch(ctx, base+"/SHA256SUMS.sig", 1<<10)
	if err != nil {
		return nil, err
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || !ed25519.Verify(key, sums, signature) {
		return nil, errors.New("SHA256SUMS is not signed by the yabber release key; refusing to update")
	}
	checksums := make(map[string]string)
	for _, line := range strings.Split(string(sums), "\n") {
		if sum, name, ok := strings.Cut(line, "  "); ok {
			checksums[name] = sum
		}
	}
	return checksums, nil
}

func fetch(ctx context.Context, url string, limit int64) ([]byte, error) {
	body, err := get(ctx, url)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return io.ReadAll(io.LimitReader(body, limit))
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
