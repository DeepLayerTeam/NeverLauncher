package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
)

// guardCompatClassName0504 validates signed JVM binary class names.
func guardCompatClassName0504(class string) bool {
	if len(class) == 0 || len(class) > 256 || !strings.Contains(class, ".") {
		return false
	}
	for _, part := range strings.Split(class, ".") {
		if part == "" {
			return false
		}
		for i, r := range part {
			if r > 127 || (i == 0 && !(unicode.IsLetter(r) || r == '_' || r == '$')) ||
				(i > 0 && !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '$')) {
				return false
			}
		}
	}
	return true
}

// guardLoaderConfig0504 materializes only previously Ed25519-verified policy
// artifact entries into the guarded Java premain. This is not a new trust root.
// Loader code-source SHA-256 is rechecked inside the JVM at class definition.
func guardLoaderConfig0504(root string, p guardCompatPolicy0502) (string, error) {
	loader := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(p.Loader, "-", ""), "_", ""))
	switch loader {
	case "vanilla", "fabric", "quilt", "forge", "neoforge":
	default:
		return "", fmt.Errorf("Guard unknown Trusted JVM loader %q", p.Loader)
	}
	var library []guardCompatArtifact0502
	for _, a := range p.Artifacts {
		if a.Kind != "loader-library" {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(a.Path), ".jar") || !guardCompatRel0502(a.Path) {
			return "", fmt.Errorf("Guard invalid loader library path %q", a.Path)
		}
		for _, revoked := range p.RevokedDigests {
			if revoked == a.SHA256 {
				return "", errors.New("Guard revoked loader library")
			}
		}
		hash, err := guardCompatHashFile0502(root, a.Path)
		if err != nil {
			return "", err
		}
		if hash != a.SHA256 {
			return "", fmt.Errorf("Guard loader library digest changed: %s", a.Path)
		}
		library = append(library, a)
	}
	if (loader == "vanilla" && len(library) != 0) || (loader != "vanilla" && len(library) == 0) || len(library) > 128 {
		return "", errors.New("Guard loader library list inconsistent with signed loader identity")
	}
	var out strings.Builder
	fmt.Fprintf(&out, "loader.id=%s\nloader.count=%d\n", loader, len(library))
	for i, a := range library {
		// Go path validation is relative to the checked client root.
		path, err := guardCompatPath0502(root, a.Path)
		if err != nil {
			return "", err
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&out, "loader.%d.path=%s\nloader.%d.sha256=%s\n", i,
			base64.StdEncoding.EncodeToString([]byte(absolute)), i, a.SHA256)
	}
	if len(p.LoaderClassBytes) > 4096 {
		return "", errors.New("Guard loader class-byte binding count exceeded")
	}
	fmt.Fprintf(&out, "loader.class.count=%d\n", len(p.LoaderClassBytes))
	for i, cls := range p.LoaderClassBytes {
		if !guardCompatClassName0504(cls.Class) || !guardCompatHex0502(cls.SHA256) {
			return "", errors.New("Guard invalid loader class-byte binding")
		}
		fmt.Fprintf(&out, "loader.class.%d.name=%s\nloader.class.%d.sha256=%s\n", i,
			base64.StdEncoding.EncodeToString([]byte(cls.Class)), i, cls.SHA256)
	}
	return out.String(), nil
}
