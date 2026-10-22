//go:build worker

package main

import "github.com/lsongdev/yabber/workers"

// Build with -tags worker to enable inline JavaScript Worker handlers.
func init() {
	extensions = append(extensions, workers.Option())
}
