package yabber

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const savedHeader = `# Managed by yabber: changes made through the management API rewrite this
# file, and the previous version is kept as %s.bak.
`

// Save writes config to path as YAML, for programs that change the
// configuration at runtime and want a restart to keep the change. The file
// is replaced atomically with its permissions kept, and the previous version
// is saved as path.bak. Comments in the previous file are not preserved.
func Save(path string, config Config) error {
	var buffer bytes.Buffer
	fmt.Fprintf(&buffer, savedHeader, filepath.Base(path))
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(config); err != nil {
		return err
	}
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
	if _, err = file.Write(buffer.Bytes()); err == nil {
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
