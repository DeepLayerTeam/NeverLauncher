package main

// The 1.0 public distribution can only contain the exact native installer
// bytes approved by the independent GA verifier. The offline release builder
// verifies this receipt and includes all of its members as REQUIRED release
// artifacts. This does not replace the independent Ed25519 verification in
// scripts/release/publication_ga.py, which runs before staging and again
// immediately before the public GitHub write.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const supportedPlatformGAReceipt1000 = "SUPPORTED_PLATFORM_GA_1000.json"

var supportedPlatformGAProject1000 = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,45}$`)
var supportedPlatformGASHA1000 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var supportedPlatformGACommit1000 = regexp.MustCompile(`^[0-9a-f]{40}$`)

type supportedPlatformGAFile1000 struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type supportedPlatformGAReport1000 struct {
	Schema                    string                                 `json:"schema"`
	Version                   string                                 `json:"version"`
	Commit                    string                                 `json:"commit"`
	Project                   string                                 `json:"project"`
	SourceIndexSHA256         string                                 `json:"sourceIndexSha256"`
	IndependentApprovalSHA256 string                                 `json:"independentApprovalSha256"`
	Status                    string                                 `json:"status"`
	Packages                  map[string]supportedPlatformGAFile1000 `json:"packages"`
	SupportedTargets          []string                               `json:"supportedTargets"`
}

func supportedPlatformGARequired1000(version string) bool {
	return compatibilityVersionAtLeast(version, 1, 0, 0)
}

func verifySupportedPlatformGA1000(dir, version, commit string) ([]string, error) {
	if !supportedPlatformGARequired1000(version) {
		return nil, nil
	}
	// Upgrading a major/minor version requires a deliberate review of the
	// independent evidence domain; never let the generic SemVer check bypass it.
	if version != "1.0.0" {
		return nil, errors.New("Supported Platform GA: текущая политика разрешает только 1.0.0")
	}
	path := filepath.Join(dir, supportedPlatformGAReceipt1000)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 64*1024 {
		return nil, errors.New("Supported Platform GA: отсутствует реальное подтверждение шести нативных пакетов")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc supportedPlatformGAReport1000
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("Supported Platform GA: неверный формат подтверждения: %w", err)
	}
	var more any
	if err := decoder.Decode(&more); err != io.EOF {
		return nil, errors.New("Supported Platform GA: дополнительные данные или повреждённый JSON")
	}
	if doc.Schema != "launcher.supported-platform-ga/1.0.0" || doc.Version != version ||
		doc.Status != "independently-approved-exact-native-packages" ||
		!supportedPlatformGACommit1000.MatchString(doc.Commit) ||
		(commit != "" && doc.Commit != commit) ||
		!supportedPlatformGAProject1000.MatchString(doc.Project) ||
		!supportedPlatformGASHA1000.MatchString(doc.SourceIndexSHA256) ||
		!supportedPlatformGASHA1000.MatchString(doc.IndependentApprovalSHA256) {
		return nil, errors.New("Supported Platform GA: несоответствие версии, SHA, коммита или независимого одобрения")
	}
	targets := []string{"windows-x64", "windows-arm64", "linux-x64", "linux-arm64", "macos-x64", "macos-arm64"}
	if len(doc.SupportedTargets) != len(targets) {
		return nil, errors.New("Supported Platform GA: неполная матрица поддерживаемых платформ")
	}
	for i, target := range targets {
		if doc.SupportedTargets[i] != target {
			return nil, errors.New("Supported Platform GA: матрица целевых платформ изменена")
		}
	}
	names := []string{supportedPlatformGAReceipt1000}
	for _, target := range targets {
		parts := strings.Split(target, "-")
		osName, arch := parts[0], parts[1]
		suffix := ".deb"
		if osName == "windows" {
			suffix = ".exe"
		} else if osName == "macos" {
			suffix = ".pkg"
		}
		name := fmt.Sprintf("launcher-%s-%s-%s-%s%s", version, doc.Project, osName, arch, suffix)
		names = append(names, name)
		if osName == "linux" {
			names = append(names, name+".asc")
		}
	}
	if len(doc.Packages) != 8 {
		return nil, errors.New("Supported Platform GA: требуются шесть инсталляторов и две подписи Linux")
	}
	for _, name := range names[1:] {
		row, ok := doc.Packages[name]
		if !ok || !supportedPlatformGASHA1000.MatchString(row.SHA256) || row.Size <= 0 {
			return nil, fmt.Errorf("Supported Platform GA: отсутствует проверенный файл %s", name)
		}
		asset := filepath.Join(dir, name)
		info, err := os.Lstat(asset)
		if err != nil || !info.Mode().IsRegular() || info.Size() != row.Size {
			return nil, fmt.Errorf("Supported Platform GA: файл изменён, не существует или является ссылкой: %s", name)
		}
		hash, size, err := hashFile(asset)
		if err != nil || size != row.Size || hash != row.SHA256 {
			return nil, fmt.Errorf("Supported Platform GA: хеш финального установщика не совпадает: %s", name)
		}
	}
	return names, nil
}
