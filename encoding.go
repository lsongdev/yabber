package yabber

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Configuration types encode to YAML and JSON with the same field names.
// Decoding is strict in both formats: unknown fields are errors, except on
// sites and routes, where unknown keys are extension handlers that compile
// rejects unless registered with WithHandler.

// Duration is a time.Duration written as a string such as "30s".
type Duration time.Duration

func (d Duration) String() string { return time.Duration(d).String() }

func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

func (d *Duration) UnmarshalText(text []byte) error {
	value, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("invalid duration %q", text)
	}
	*d = Duration(value)
	return nil
}

func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var text string
	if err := unmarshal(&text); err != nil {
		return err
	}
	return d.UnmarshalText([]byte(text))
}

func (s Site) MarshalYAML() (any, error) {
	type plain Site
	return marshalYAMLWithExtensions(plain(s), s.Extensions)
}

func (s *Site) UnmarshalYAML(unmarshal func(any) error) error {
	type plain Site
	var raw struct {
		Site       plain          `yaml:",inline"`
		Extensions map[string]any `yaml:",inline"`
	}
	if err := unmarshal(&raw); err != nil {
		return err
	}
	*s = Site(raw.Site)
	s.Extensions = raw.Extensions
	return nil
}

func (s Site) MarshalJSON() ([]byte, error) {
	type plain Site
	return marshalJSONWithExtensions(plain(s), s.Extensions)
}

func (s *Site) UnmarshalJSON(data []byte) error {
	type plain Site
	return unmarshalJSONWithExtensions(data, (*plain)(s), &s.Extensions)
}

func (r Route) MarshalYAML() (any, error) {
	type plain Route
	return marshalYAMLWithExtensions(plain(r), r.Extensions)
}

func (r *Route) UnmarshalYAML(unmarshal func(any) error) error {
	type plain Route
	var raw struct {
		Route      plain          `yaml:",inline"`
		Extensions map[string]any `yaml:",inline"`
	}
	if err := unmarshal(&raw); err != nil {
		return err
	}
	*r = Route(raw.Route)
	r.Extensions = raw.Extensions
	return nil
}

func (r Route) MarshalJSON() ([]byte, error) {
	type plain Route
	return marshalJSONWithExtensions(plain(r), r.Extensions)
}

func (r *Route) UnmarshalJSON(data []byte) error {
	type plain Route
	return unmarshalJSONWithExtensions(data, (*plain)(r), &r.Extensions)
}

// Proxy, Files, Respond and Redirect accept a string shorthand for their
// main field.

func (p *Proxy) UnmarshalYAML(unmarshal func(any) error) error {
	type plain Proxy
	return unmarshalYAMLShorthand(unmarshal, &p.Upstream, (*plain)(p))
}

func (p *Proxy) UnmarshalJSON(data []byte) error {
	type plain Proxy
	return unmarshalJSONShorthand(data, &p.Upstream, (*plain)(p))
}

func (f *Files) UnmarshalYAML(unmarshal func(any) error) error {
	type plain Files
	return unmarshalYAMLShorthand(unmarshal, &f.Root, (*plain)(f))
}

func (f *Files) UnmarshalJSON(data []byte) error {
	type plain Files
	return unmarshalJSONShorthand(data, &f.Root, (*plain)(f))
}

func (r *Respond) UnmarshalYAML(unmarshal func(any) error) error {
	type plain Respond
	return unmarshalYAMLShorthand(unmarshal, &r.Body, (*plain)(r))
}

func (r *Respond) UnmarshalJSON(data []byte) error {
	type plain Respond
	return unmarshalJSONShorthand(data, &r.Body, (*plain)(r))
}

func (r *Redirect) UnmarshalYAML(unmarshal func(any) error) error {
	type plain Redirect
	return unmarshalYAMLShorthand(unmarshal, &r.To, (*plain)(r))
}

func (r *Redirect) UnmarshalJSON(data []byte) error {
	type plain Redirect
	return unmarshalJSONShorthand(data, &r.To, (*plain)(r))
}

// unmarshalYAMLShorthand decodes a scalar into field, or a mapping into full.
// It uses the legacy unmarshaler signature because, unlike yaml.Node.Decode,
// it keeps the decoder's KnownFields setting.
func unmarshalYAMLShorthand(unmarshal func(any) error, field *string, full any) error {
	var value string
	if err := unmarshal(&value); err == nil {
		*field = value
		return nil
	}
	return unmarshal(full)
}

func unmarshalJSONShorthand(data []byte, field *string, full any) error {
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte(`"`)) {
		return json.Unmarshal(data, field)
	}
	return decodeJSONStrict(data, full)
}

func decodeJSONStrict(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("unexpected data after JSON value")
	}
	return nil
}

func marshalYAMLWithExtensions(plain any, extensions map[string]any) (any, error) {
	var node yaml.Node
	if err := node.Encode(plain); err != nil {
		return nil, err
	}
	for _, name := range slices.Sorted(maps.Keys(extensions)) {
		var key, value yaml.Node
		key.SetString(name)
		if err := value.Encode(extensions[name]); err != nil {
			return nil, err
		}
		node.Content = append(node.Content, &key, &value)
	}
	return &node, nil
}

func marshalJSONWithExtensions(plain any, extensions map[string]any) ([]byte, error) {
	data, err := json.Marshal(plain)
	if err != nil || len(extensions) == 0 {
		return data, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	for name, value := range extensions {
		if fields[name], err = json.Marshal(value); err != nil {
			return nil, err
		}
	}
	return json.Marshal(fields)
}

// unmarshalJSONWithExtensions moves object keys that are not fields of
// plain into extensions and strictly decodes the rest.
func unmarshalJSONWithExtensions(data []byte, plain any, extensions *map[string]any) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	known := jsonFieldNames(reflect.TypeOf(plain).Elem())
	*extensions = nil
	for name, raw := range fields {
		if known[name] {
			continue
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
		if *extensions == nil {
			*extensions = make(map[string]any)
		}
		(*extensions)[name] = value
		delete(fields, name)
	}
	rest, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	return decodeJSONStrict(rest, plain)
}

// jsonFieldNames lists the JSON object keys of a struct, including fields
// promoted from embedded structs.
func jsonFieldNames(t reflect.Type) map[string]bool {
	names := make(map[string]bool)
	for field := range t.Fields() {
		tag := field.Tag.Get("json")
		if tag == "-" || !field.IsExported() {
			continue
		}
		if field.Anonymous && tag == "" && field.Type.Kind() == reflect.Struct {
			maps.Copy(names, jsonFieldNames(field.Type))
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == "" {
			name = field.Name
		}
		names[name] = true
	}
	return names
}
