package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// UUID mappings contain account identifiers. Never publish them in a
// world-readable file, overwrite an existing operator decision, or follow an
// output symlink. stdout remains available explicitly for automation.
func writePrivateIdentityReport0334(path string, data any) error {
	if path == "" || path == "-" {
		printJSON(data)
		return nil
	}
	raw, e := json.MarshalIndent(data, "", "  ")
	if e != nil {
		return e
	}
	// Do not create parent directories with permissive defaults; the owner must
	// select an existing protected output directory.
	if info, e := os.Stat(filepath.Dir(path)); e != nil {
		return e
	} else if !info.IsDir() {
		return fmt.Errorf("identity report parent is not a directory")
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if _, e = f.Write(append(raw, '\n')); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	ok = true
	return nil
}
