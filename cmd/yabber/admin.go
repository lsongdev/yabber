package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/lsongdev/yabber"
	"gopkg.in/yaml.v3"
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

const savedHeader = `# Managed by yabber: changes made through the management API rewrite this
# file, and the previous version is kept as %s.bak.
`

// saver persists API changes to the configuration file. It replaces the file
// atomically, keeping its mode and the previous version beside it.
func saver(path string) func(yabber.Config) error {
	return func(config yabber.Config) error {
		var buffer bytes.Buffer
		buffer.WriteString(fmt.Sprintf(savedHeader, filepath.Base(path)))
		encoder := yaml.NewEncoder(&buffer)
		encoder.SetIndent(2)
		if err := encoder.Encode(config); err != nil {
			return err
		}
		data := buffer.Bytes()
		mode := fs.FileMode(0o600)
		if info, err := os.Stat(path); err == nil {
			mode = info.Mode().Perm()
			if previous, err := os.ReadFile(path); err == nil {
				if err := os.WriteFile(path+".bak", previous, mode); err != nil {
					return err
				}
			}
		}
		file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
		if err != nil {
			return err
		}
		defer os.Remove(file.Name())
		if _, err := file.Write(data); err == nil {
			err = file.Chmod(mode)
		}
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		return os.Rename(file.Name(), path)
	}
}
