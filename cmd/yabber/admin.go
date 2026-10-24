package main

import (
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"strings"

	"github.com/lsongdev/yabber"
)

// adminToken reads the management API token, generating it on first use.
func adminToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if token := strings.TrimSpace(string(data)); token != "" {
			return token, nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	token := rand.Text()
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", err
	}
	return token, nil
}

// saver persists API changes to the configuration file.
func saver(path string) func(yabber.Config) error {
	return func(config yabber.Config) error { return yabber.Save(path, config) }
}
