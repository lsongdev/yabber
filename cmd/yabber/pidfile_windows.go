//go:build windows

package main

import (
	"errors"
	"os"
	"strconv"
)

// pidFile records the pid on Windows, where yabber does not lock the data
// directory and cannot be reloaded by signal.
type pidFile struct {
	path string
}

func acquirePidFile(path string) (*pidFile, error) {
	if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
		return nil, err
	}
	return &pidFile{path: path}, nil
}

func (p *pidFile) release() { os.Remove(p.path) }

func reloadCommand([]string) error {
	return errors.New("reload is not supported on Windows; restart the service instead")
}
