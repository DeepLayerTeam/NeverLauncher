package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func buildDesktopPackage(ver, artifactDir, out, platform string) error {
	candidates := filterDesktopPlatforms(desktopPackagePlatforms(ver), platform)
	if len(candidates) == 0 {
		return fmt.Errorf("неизвестная desktop-платформа: %s", platform)
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	selected := []DesktopPackagePlatform{}
	checksums := []string{}
	for _, item := range candidates {
		src := filepath.Join(artifactDir, item.Artifact)
		st, err := os.Stat(src)
		if err != nil {
			continue
		}
		if st.IsDir() {
			continue
		}
		dst := filepath.Join(out, item.Artifact)
		if err := copyFileAtomic(src, dst); err != nil {
			return err
		}
		sum, size, err := hashFile(dst)
		if err != nil {
			return err
		}
		item.Size, item.SHA256, item.Status = size, sum, "packaged"
		selected = append(selected, item)
		checksums = append(checksums, sum+"  "+item.Artifact)
	}
	if len(selected) == 0 {
		return errors.New("desktop package не содержит ни одного реально собранного native artifact")
	}
	sort.Strings(checksums)
	manifest := DesktopPackageManifest{SchemaVersion: cliSchemaVersion, GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano), ToolVersion: version, Version: ver, Platforms: selected, ChecksumsFile: "SHA256SUMS.desktop"}
	if err := writeJSONFile(filepath.Join(out, "DESKTOP_PACKAGE_MANIFEST.json"), manifest); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, manifest.ChecksumsFile), []byte(strings.Join(checksums, "\n")+"\n"), 0o644)
}

func verifyDesktopPackage(dir string) error {
	raw, err := os.ReadFile(filepath.Join(dir, "DESKTOP_PACKAGE_MANIFEST.json"))
	if err != nil {
		return err
	}
	var manifest DesktopPackageManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	if manifest.SchemaVersion == "" || manifest.Version == "" || len(manifest.Platforms) == 0 {
		return errors.New("desktop package manifest неполон")
	}
	expectedLines := map[string]string{}
	f, err := os.Open(filepath.Join(dir, manifest.ChecksumsFile))
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) == 2 {
			expectedLines[parts[1]] = parts[0]
		}
	}
	_ = f.Close()
	if err := scanner.Err(); err != nil {
		return err
	}
	for _, item := range manifest.Platforms {
		if item.Status != "packaged" || item.Artifact == "" || item.SHA256 == "" || item.Size <= 0 {
			return fmt.Errorf("desktop artifact metadata invalid: %s", item.Artifact)
		}
		sum, size, err := hashFile(filepath.Join(dir, item.Artifact))
		if err != nil {
			return err
		}
		if size != item.Size || !strings.EqualFold(sum, item.SHA256) {
			return fmt.Errorf("desktop artifact checksum/size mismatch: %s", item.Artifact)
		}
		if !strings.EqualFold(expectedLines[item.Artifact], sum) {
			return fmt.Errorf("SHA256SUMS.desktop mismatch: %s", item.Artifact)
		}
	}
	fmt.Printf("Desktop package проверен: %d artifact(s)\n", len(manifest.Platforms))
	return nil
}
