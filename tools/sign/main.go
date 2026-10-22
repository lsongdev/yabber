// Command sign signs release checksums for yabber update and install.sh:
//
//	YABBER_SIGNING_KEY=... go run ./tools/sign < SHA256SUMS > SHA256SUMS.sig
//
// The key is a base64 Ed25519 seed; its public half is compiled into
// cmd/yabber and install.sh. The signature is written in base64.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sign:", err)
		os.Exit(1)
	}
}

func run() error {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("YABBER_SIGNING_KEY")))
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("YABBER_SIGNING_KEY must be a base64 Ed25519 seed")
	}
	message, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(seed), message)
	_, err = fmt.Println(base64.StdEncoding.EncodeToString(signature))
	return err
}
