// Package workers runs inline JavaScript Worker scripts and registers them
// with yabber as the "worker" handler. It is separate from the core package
// so that gateways which do not use workers do not link a JavaScript engine.
//
//	server, err := yabber.New(cfg, workers.Option())
//
//	sites:
//	  - hosts: [hello.example.com]
//	    worker: |
//	      export default {
//	        async fetch(request, env) { return new Response("hello") }
//	      }
package workers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/lsongdev/yabber"
)

// Name is the handler key used in configurations.
const Name = "worker"

// Config configures a worker handler. In YAML and JSON it may be written as
// the script alone.
type Config struct {
	Script string            `yaml:"script" json:"script"`
	Env    map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
}

func (c *Config) UnmarshalYAML(unmarshal func(any) error) error {
	if err := unmarshal(&c.Script); err == nil {
		return nil
	}
	type plain Config
	return unmarshal((*plain)(c))
}

// Option registers the worker handler with a yabber server.
func Option() yabber.Option {
	return yabber.WithHandler(Name, Factory)
}

// Factory builds a worker handler from its configuration.
func Factory(decode func(any) error) (http.Handler, error) {
	var config Config
	if err := decode(&config); err != nil {
		return nil, err
	}
	if strings.TrimSpace(config.Script) == "" {
		return nil, errors.New("worker script is required")
	}
	return New(config.Script, config.Env)
}
