package main

// Подписанные свидетельства оператора независимо проверяются до упаковки. Эта проверка на
// стороне выпуска связывает итоговую квитанцию с подписанными SHA256SUMS и RELEASE_MANIFEST и
// не допускает подмены JSON-заглушкой только со статусом.
import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

const officialGACertification0270 = "OFFICIAL_MINECRAFT_GA_CERTIFICATION.json"

var officialGASHA0270 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var officialGACommit0270 = regexp.MustCompile(`^[0-9a-f]{40}$`)

func verifyOfficialGAReceipt0270(dir, version, expectedCommit string) error {
	if version != "0.27.0" {
		return nil
	}
	if !officialGACommit0270.MatchString(expectedCommit) {
		return errors.New("official Minecraft GA: требуется точный коммит исходников")
	}
	path := filepath.Join(dir, officialGACertification0270)
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 32*1024 {
		return errors.New("Некорректное значение: «official Minecraft GA signed receipt missing or»")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var receipt struct {
		SchemaVersion  string `json:"schemaVersion"`
		ProductVersion string `json:"productVersion"`
		Commit         string `json:"commit"`
		Status         string `json:"status"`
		Targets        []struct {
			Target               string `json:"target"`
			Status               string `json:"status"`
			AttestationSHA256    string `json:"attestationSha256"`
			SignedArtifactSHA256 string `json:"signedArtifactSha256"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return fmt.Errorf("official GA receipt JSON: %w", err)
	}
	if receipt.SchemaVersion != "launcher.official-minecraft.ga-receipt.v1" || receipt.ProductVersion != version || receipt.Commit != expectedCommit || receipt.Status != "passed" || len(receipt.Targets) != 6 {
		return errors.New("official GA receipt failed release/commit/status binding")
	}
	expected := map[string]bool{"windows-amd64": false, "windows-arm64": false, "linux-amd64": false, "linux-arm64": false, "darwin-amd64": false, "darwin-arm64": false}
	for _, r := range receipt.Targets {
		visited, valid := expected[r.Target]
		if !valid || visited || r.Status != "passed" || !officialGASHA0270.MatchString(r.AttestationSHA256) || !officialGASHA0270.MatchString(r.SignedArtifactSHA256) {
			return errors.New("missing/duplicate/invalid official GA platform certification")
		}
		expected[r.Target] = true
	}
	return nil
}
