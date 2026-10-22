// Command yabber runs a gateway from a YAML configuration file.
//
//	yabber [run]  -d /var/lib/yabber -c /etc/yabber/config.yaml
//	yabber check  -d DIR [-c FILE]
//	yabber reload -d DIR
//	yabber update [-check]
//	yabber version
//
// The data directory (-d) holds state yabber writes: ACME accounts and
// certificates, and the pid file. The configuration defaults to
// DIR/config.yaml; without -d, the data directory is the configuration's
// directory.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/lsongdev/yabber"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// extensions lists optional handlers compiled in with build tags.
var extensions []yabber.Option

const usage = `usage: yabber [command] [flags]

commands:
  run       serve (default)
  check     validate the configuration and exit
  reload    make the running instance reload its configuration
  update    replace this binary with the latest release
  version   print the version

Run "yabber <command> -h" for a command's flags.
`

func main() {
	args := os.Args[1:]
	command := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command, args = args[0], args[1:]
	}
	var err error
	switch command {
	case "run":
		err = runCommand(args)
	case "check":
		err = checkCommand(args)
	case "reload":
		err = reloadCommand(args)
	case "update":
		err = updateCommand(args)
	case "version":
		fmt.Println(versionString())
	case "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", command, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "yabber:", err)
		os.Exit(1)
	}
}

// paths are the data directory and configuration file of an instance.
type paths struct {
	dir, config string
}

func (p *paths) register(flags *flag.FlagSet) {
	flags.StringVar(&p.dir, "d", "", "data directory (default: the configuration's directory)")
	flags.StringVar(&p.config, "c", "", "configuration file (default: DIR/config.yaml)")
}

// resolve fills in whichever of the two was not given.
func (p *paths) resolve() {
	switch {
	case p.dir == "" && p.config == "":
		p.dir = "."
	case p.dir == "":
		p.dir = filepath.Dir(p.config)
	}
	if p.config == "" {
		p.config = filepath.Join(p.dir, "config.yaml")
	}
}

func (p paths) pidFile() string {
	return filepath.Join(p.dir, "yabber.pid")
}

func checkCommand(args []string) error {
	flags := flag.NewFlagSet("check", flag.ExitOnError)
	var p paths
	p.register(flags)
	flags.Parse(args)
	p.resolve()
	config, err := yabber.Load(p.config)
	if err != nil {
		return err
	}
	if err := yabber.Validate(config, append(extensions, yabber.WithDataDir(p.dir))...); err != nil {
		return err
	}
	fmt.Println("configuration ok:", p.config)
	return nil
}

func versionString() string {
	revision := ""
	if commit := buildSetting("vcs.revision", ""); len(commit) >= 7 {
		revision = " (" + commit[:7]
		if buildSetting("vcs.modified", "") == "true" {
			revision += "+dirty"
		}
		revision += ")"
	}
	return fmt.Sprintf("yabber %s%s %s/%s %s", version, revision, runtime.GOOS, runtime.GOARCH, runtime.Version())
}
