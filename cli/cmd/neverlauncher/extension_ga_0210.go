package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	neverExtensionsPackageVersion0210  = "1.0"
	neverExtensionsManifestVersion0210 = "2.0"
	neverExtensionsHostVersion0210     = "1.0"
	neverExtensionsAPIVersion0210      = "1.0"
	neverExtensionsLegacyAPI020        = "3.7"
	neverExtensionsSDKVersion0210      = "0.21.0"
)

func supportedExtensionAPI0210(raw string) bool {
	switch strings.TrimSpace(raw) {
	case neverExtensionsAPIVersion0210, "1.0.0", "v1", "v1.0", "v1.0.0", neverExtensionsLegacyAPI020, "3.7.0":
		return true
	default:
		return false
	}
}

// supportsHostHello0210 mirrors the Backend compatibility rule: 0.20 signed/source
// manifests may use the legacy 3.7 marker and an old SDK that did not send an
// Extension API field. New API v1 manifests must explicitly negotiate API v1.
func supportsHostHello0210(manifestAPI, helloAPI string) bool {
	manifestAPI = strings.TrimSpace(manifestAPI)
	helloAPI = strings.TrimSpace(helloAPI)
	legacy := manifestAPI == neverExtensionsLegacyAPI020 || manifestAPI == "3.7.0"
	if legacy && (helloAPI == "" || helloAPI == neverExtensionsLegacyAPI020 || helloAPI == "3.7.0") {
		return true
	}
	if !supportedExtensionAPI0210(manifestAPI) {
		return false
	}
	switch helloAPI {
	case neverExtensionsAPIVersion0210, "1.0.0", "v1", "v1.0", "v1.0.0":
		return true
	default:
		return false
	}
}

func handleExtensionGA0210(args []string) error {
	if len(args) == 0 || args[0] == "status" || args[0] == "contract" {
		printJSON(map[string]any{
			"status":                "ga",
			"productVersion":        "0.21.0",
			"packageFormatVersion":  neverExtensionsPackageVersion0210,
			"manifestSchemaVersion": neverExtensionsManifestVersion0210,
			"hostProtocolVersion":   neverExtensionsHostVersion0210,
			"extensionApiVersion":   neverExtensionsAPIVersion0210,
			"legacyApiAliases":      []string{neverExtensionsLegacyAPI020},
			"sdkVersion":            neverExtensionsSDKVersion0210,
		})
		return nil
	}
	switch args[0] {
	case "upgrade-source":
		return extensionUpgradeSource0210(args[1:])
	default:
		return fmt.Errorf("unknown extension ga command %q; use status|contract|upgrade-source", args[0])
	}
}

func extensionUpgradeSource0210(args []string) error {
	root := "."
	if len(args) > 0 && !strings.HasPrefix(args[0], "--") {
		root = args[0]
	}
	root = filepath.Clean(root)
	if strings.EqualFold(filepath.Ext(root), ".nlext") {
		return errors.New("signed .nlext packages are immutable; unpack source, change api to 1.0, rebuild and re-sign")
	}
	manifestPath := canonicalExtensionManifestPath0201(root)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var manifest CanonicalExtensionManifest0201
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return fmt.Errorf("decode %s: %w", manifestPath, err)
	}
	previousAPI := strings.TrimSpace(manifest.API)
	if !supportedExtensionAPI0210(previousAPI) {
		return fmt.Errorf("source uses unsupported extension api %q", previousAPI)
	}
	manifest.API = neverExtensionsAPIVersion0210
	normalized, _, err := normalizeCanonicalExtension0201(manifest)
	if err != nil {
		return err
	}
	normalized.API = neverExtensionsAPIVersion0210
	manifestBytes, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return err
	}
	manifestBytes = append(manifestBytes, '\n')
	changed := previousAPI != neverExtensionsAPIVersion0210 || !bytes.Equal(data, manifestBytes)
	if changed {
		if err := atomicWriteCLI0210(manifestPath, manifestBytes, 0o644); err != nil {
			return err
		}
	}

	moduleChanges := []string{}
	for _, rel := range []string{"backend/go.mod", "cli/go.mod"} {
		path := filepath.Join(root, rel)
		b, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		next := string(b)
		for _, old := range []string{"v0.20.10", "v0.20.11", "v0.20.12"} {
			next = strings.ReplaceAll(next, old, "v"+neverExtensionsSDKVersion0210)
		}
		if next != string(b) {
			st, statErr := os.Stat(path)
			if statErr != nil {
				return statErr
			}
			if err := atomicWriteCLI0210(path, []byte(next), st.Mode().Perm()); err != nil {
				return err
			}
			moduleChanges = append(moduleChanges, filepath.ToSlash(rel))
		}
	}
	printJSON(map[string]any{
		"upgraded":                true,
		"root":                    root,
		"manifest":                manifestPath,
		"previousApi":             previousAPI,
		"extensionApiVersion":     neverExtensionsAPIVersion0210,
		"changed":                 changed,
		"moduleFiles":             moduleChanges,
		"requiresRepackAndResign": true,
	})
	return nil
}

func atomicWriteCLI0210(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".neverextensions-ga-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
