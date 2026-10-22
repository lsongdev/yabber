//go:build !windows

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// pidFile is an exclusively locked file holding the running instance's pid.
// The lock, not the file's existence, decides whether an instance runs: the
// kernel releases it when the process exits, so a stale file after a crash
// never blocks a start or misdirects a reload. One instance owns a data
// directory; instances with different directories run side by side.
type pidFile struct {
	file *os.File
}

func acquirePidFile(path string) (*pidFile, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("another yabber is running with this data directory (%s)", path)
		}
		return nil, err
	}
	if err := file.Truncate(0); err == nil {
		_, err = file.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	}
	return &pidFile{file: file}, nil
}

func (p *pidFile) release() {
	os.Remove(p.file.Name())
	p.file.Close()
}

// runningPid returns the pid of the instance holding the lock on path.
func runningPid(path string) (int, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, errors.New("yabber is not running with this data directory")
	}
	if err != nil {
		return 0, err
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err == nil {
		syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		return 0, errors.New("yabber is not running with this data directory (stale pid file)")
	}
	data := make([]byte, 32)
	n, _ := file.Read(data)
	pid, err := strconv.Atoi(strings.TrimSpace(string(data[:n])))
	if err != nil {
		return 0, fmt.Errorf("unreadable pid file %s", path)
	}
	return pid, nil
}

func reloadCommand(args []string) error {
	flags := flag.NewFlagSet("reload", flag.ExitOnError)
	var p paths
	p.register(flags)
	flags.Parse(args)
	p.resolve()
	pid, err := runningPid(p.pidFile())
	if err != nil {
		return err
	}
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		return fmt.Errorf("signal pid %d: %w", pid, err)
	}
	fmt.Printf("sent reload to pid %d; check the log for the result\n", pid)
	return nil
}
