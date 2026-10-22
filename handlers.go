package yabber

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"os"
	"path"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// HandlerFactory builds an extension handler. decode strictly decodes the
// handler's configuration into a value, as YAML decoding would.
type HandlerFactory func(decode func(any) error) (http.Handler, error)

func (c *compiler) handler(config Handler) (http.Handler, error) {
	count := len(config.Extensions)
	for _, set := range []bool{config.Proxy != nil, config.Files != nil, config.Respond != nil, config.Redirect != nil} {
		if set {
			count++
		}
	}
	if count != 1 {
		return nil, errors.New("exactly one handler is required: proxy, files, respond, redirect or a registered extension")
	}
	switch {
	case config.Proxy != nil:
		return c.proxy(*config.Proxy)
	case config.Files != nil:
		return filesHandler(*config.Files)
	case config.Respond != nil:
		return respondHandler(*config.Respond)
	case config.Redirect != nil:
		return redirectHandler(*config.Redirect)
	}
	for name, value := range config.Extensions {
		factory := c.opts.handlers[name]
		if factory == nil {
			return nil, unknownExtension(name)
		}
		handler, err := factory(func(target any) error { return decodeExtension(value, target) })
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		return handler, nil
	}
	panic("unreachable")
}

// checkExtensions reports keys that are neither fields nor registered
// handlers, which in practice are typos.
func (c *compiler) checkExtensions(extensions map[string]any) error {
	for _, name := range slices.Sorted(maps.Keys(extensions)) {
		if c.opts.handlers[name] == nil {
			return unknownExtension(name)
		}
	}
	return nil
}

func unknownExtension(name string) error {
	return fmt.Errorf("unknown field or handler %q", name)
}

func decodeExtension(value, target any) error {
	data, err := yaml.Marshal(value)
	if err != nil {
		return err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func filesHandler(config Files) (http.Handler, error) {
	if config.Root == "" {
		return nil, errors.New("files root is required")
	}
	info, err := os.Stat(config.Root)
	if err != nil {
		return nil, fmt.Errorf("files root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("files root %s is not a directory", config.Root)
	}
	handler := http.FileServer(publicFileSystem{root: http.Dir(config.Root), browse: config.Browse})
	if config.StripPrefix != "" {
		handler = stripPrefix(config.StripPrefix, handler)
	}
	return handler, nil
}

// publicFileSystem hides dotfiles such as .git and .env, and, unless browse
// is set, directories that have no index.html.
type publicFileSystem struct {
	root   http.FileSystem
	browse bool
}

func (f publicFileSystem) Open(name string) (http.File, error) {
	for part := range strings.SplitSeq(name, "/") {
		if strings.HasPrefix(part, ".") && part != ".well-known" {
			return nil, fs.ErrNotExist
		}
	}
	file, err := f.root.Open(name)
	if err != nil || f.browse {
		return file, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if info.IsDir() {
		index, err := f.root.Open(path.Join(name, "index.html"))
		if err != nil {
			file.Close()
			return nil, fs.ErrNotExist
		}
		index.Close()
	}
	return file, nil
}

func respondHandler(config Respond) (http.Handler, error) {
	status := config.Status
	if status == 0 {
		status = http.StatusOK
	}
	if status < 200 || status > 599 {
		return nil, fmt.Errorf("invalid response status %d", status)
	}
	header := make(http.Header, len(config.Headers))
	for name, value := range config.Headers {
		header.Set(name, value)
	}
	body := config.Body
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		maps.Copy(w.Header(), header)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}), nil
}

func redirectHandler(config Redirect) (http.Handler, error) {
	if config.To == "" {
		return nil, errors.New("redirect target is required")
	}
	status := config.Status
	if status == 0 {
		status = http.StatusPermanentRedirect
	}
	if status < 300 || status > 399 {
		return nil, fmt.Errorf("redirect status must be 3xx, got %d", status)
	}
	if !config.PreservePath {
		return http.RedirectHandler(config.To, status), nil
	}
	base := strings.TrimSuffix(config.To, "/")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, base+r.URL.RequestURI(), status)
	}), nil
}
