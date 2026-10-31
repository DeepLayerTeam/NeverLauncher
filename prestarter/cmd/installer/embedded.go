package main

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// A release builder substitutes a VERIFIED signed bundle here before building
// a single-file Windows installer. An empty zip means external bundle mode.
//
//go:embed embedded.bundle.zip
var embeddedBundle []byte

func unpackEmbedded() (string, bool, error) {
	reader, err := zip.NewReader(bytes.NewReader(embeddedBundle), int64(len(embeddedBundle)))
	if err != nil {
		return "", false, err
	}
	if len(reader.File) == 0 {
		return "", false, nil
	}
	tmp, err := os.MkdirTemp("", "launcher-verified-installer-*")
	if err != nil {
		return "", false, err
	}
	success := false
	defer func() {
		if !success {
			os.RemoveAll(tmp)
		}
	}()
	var total uint64
	offline := false
	for _, entry := range reader.File {
		name := entry.Name
		if strings.Contains(name, "\\") || strings.HasPrefix(name, "/") || strings.Contains(name, ":") || filepath.Clean(name) == ".." || strings.HasPrefix(filepath.Clean(name), ".."+string(filepath.Separator)) {
			return "", false, fmt.Errorf("unsafe embedded path: %s", name)
		}
		if entry.Mode()&os.ModeSymlink != 0 {
			return "", false, errors.New("embedded symlink rejected")
		}
		if entry.UncompressedSize64 > 3<<30 {
			return "", false, errors.New("oversized embedded entry")
		}
		total += entry.UncompressedSize64
		if total > 12<<30 || len(reader.File) > 50000 {
			return "", false, errors.New("embedded bundle resource limit exceeded")
		}
		target := filepath.Join(tmp, filepath.FromSlash(name))
		if entry.FileInfo().IsDir() {
			if err = os.MkdirAll(target, 0700); err != nil {
				return "", false, err
			}
			continue
		}
		if strings.HasPrefix(name, "objects/") || strings.HasPrefix(name, "managed-jre/") {
			offline = true
		}
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return "", false, err
		}
		input, err := entry.Open()
		if err != nil {
			return "", false, err
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
		if err != nil {
			input.Close()
			return "", false, err
		}
		n, err := io.Copy(output, io.LimitReader(input, int64(entry.UncompressedSize64)+1))
		closeErr := output.Close()
		input.Close()
		if err != nil || closeErr != nil || uint64(n) != entry.UncompressedSize64 {
			return "", false, errors.New("embedded entry size mismatch")
		}
	}
	success = true
	return tmp, offline, nil
}
