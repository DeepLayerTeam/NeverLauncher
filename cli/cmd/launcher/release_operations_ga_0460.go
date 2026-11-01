package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const operationsGAFile0460 = "OPERATIONS_GA_0460.json"
const operationsGASig0460 = "OPERATIONS_GA_0460.sig"
const operationsGADomain0460 = "neverlauncher.operations-ga.0460.v1\x00"

func operationsGARequired0460(version string) bool {
	v, ok := parseVersionTriple0158(version)
	return ok && compareVersionTriple0158(v, [3]int{0, 46, 0}) >= 0
}

type operationsGATarget0460 struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}
type operationsGAApproval0460 struct {
	Schema          string                            `json:"schema"`
	Version         string                            `json:"version"`
	SourceCommit    string                            `json:"sourceCommit"`
	IssuedAt        string                            `json:"issuedAt"`
	Operator        string                            `json:"operator"`
	SourceMachine   string                            `json:"sourceMachine"`
	RestoreMachine  string                            `json:"restoreMachine"`
	StageReceipts   map[string]string                 `json:"stageReceipts"`
	OpenApiV1Sha256 string                            `json:"openApiV1Sha256"`
	Targets         map[string]operationsGATarget0460 `json:"targets"`
	Scope           string                            `json:"scope"`
}

func operationsGARead0460(dir, name string, max int64) ([]byte, error) {
	p := filepath.Join(dir, name)
	st, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > max {
		return nil, fmt.Errorf("unsafe operations GA file: %s", name)
	}
	return os.ReadFile(p)
}

// This checks the bytes in the final release directory and a pinned external
// operator key. Neither unsigned receipts nor the bundled release key can
// authorize operations GA. Called by both signing and consumer verification.
func verifyOperationsGA0460(dir, version string, releasePublic ed25519.PublicKey) error {
	if !operationsGARequired0460(version) {
		return nil
	}
	keyPath := strings.TrimSpace(os.Getenv("LAUNCHER_OPERATIONS_GA_TRUSTED_PUBLIC_KEY_FILE"))
	if keyPath == "" {
		return errors.New("0.46.0 GA BLOCKED: independent operator trust anchor is required")
	}
	if err := ensureKeyOutsideReleaseBundle(dir, keyPath); err != nil {
		return err
	}
	pub, err := loadEd25519PublicKey(keyPath)
	if err != nil {
		return fmt.Errorf("operator trust anchor: %w", err)
	}
	if len(releasePublic) == ed25519.PublicKeySize && string(pub) == string(releasePublic) {
		return errors.New("operator and release signer must use independent Ed25519 keys")
	}
	raw, err := operationsGARead0460(dir, operationsGAFile0460, 64*1024)
	if err != nil {
		return err
	}
	encoded, err := operationsGARead0460(dir, operationsGASig0460, 1024)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, append([]byte(operationsGADomain0460), raw...), sig) {
		return errors.New("independent operations GA signature failed")
	}
	var a operationsGAApproval0460
	if err := json.Unmarshal(raw, &a); err != nil {
		return err
	}
	manifestRaw, err := operationsGARead0460(dir, "RELEASE_MANIFEST.json", 16*1024*1024)
	if err != nil {
		return err
	}
	var m struct {
		Version       string   `json:"version"`
		SourceCommit  string   `json:"sourceCommit"`
		RequiredFiles []string `json:"requiredFiles"`
		Artifacts     []struct {
			Name     string `json:"name"`
			Required bool   `json:"required"`
			Status   string `json:"status"`
			SHA256   string `json:"sha256"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(manifestRaw, &m); err != nil {
		return err
	}
	if a.Schema != "neverlauncher.operations-ga.0460.v1" || a.Version != version || m.Version != version || a.SourceCommit != m.SourceCommit || !regexp.MustCompile(`^[a-f0-9]{40}([a-f0-9]{24})?$`).MatchString(a.SourceCommit) {
		return errors.New("operations GA does not match exact source commit and version")
	}
	issued, err := time.Parse(time.RFC3339Nano, a.IssuedAt)
	if err != nil || time.Since(issued) > 14*24*time.Hour || time.Until(issued) > 5*time.Minute {
		return errors.New("operations GA expired or invalid timestamp")
	}
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	if a.Operator == "" || a.SourceMachine == a.RestoreMachine || !hex64.MatchString(a.SourceMachine) || !hex64.MatchString(a.RestoreMachine) || !hex64.MatchString(a.OpenApiV1Sha256) {
		return errors.New("independent operator, hosts or frozen API fingerprint invalid")
	}
	// The approved v1 API bytes must be the SAME source bytes pinned by the
	// release BOM, not an arbitrary separate API digest in the approval.
	bomRaw, err := operationsGARead0460(dir, releaseBOMFile03214, 16*1024*1024)
	if err != nil {
		return fmt.Errorf("frozen API BOM: %w", err)
	}
	var bom struct {
		Components []struct {
			SourceFile   string `json:"sourceFile"`
			SourceSHA256 string `json:"sourceSha256"`
		} `json:"components"`
	}
	if err := json.Unmarshal(bomRaw, &bom); err != nil {
		return err
	}
	apiEntries := 0
	for _, c := range bom.Components {
		if c.SourceFile == "schemas/openapi.yaml" {
			apiEntries++
			if c.SourceSHA256 != a.OpenApiV1Sha256 {
				return errors.New("approved API v1 differs from release BOM source bytes")
			}
		}
	}
	if apiEntries != 1 {
		return errors.New("release BOM must pin exactly one canonical API contract")
	}
	if a.Scope != "actual independent operational acceptance; canary RPO only; no assertion of physical host HA or unmeasured workload RPO" {
		return errors.New("unsupported operations GA evidence scope")
	}
	requiredStages := []string{"install-standard", "upgrade-standard", "restore-standard", "failover-network-ha"}
	if len(a.StageReceipts) != len(requiredStages) {
		return errors.New("all four independent operational receipts required")
	}
	for _, stage := range requiredStages {
		if !hex64.MatchString(a.StageReceipts[stage]) {
			return fmt.Errorf("invalid operational receipt hash: %s", stage)
		}
	}
	if len(a.Targets) != 6 {
		return errors.New("operations GA must attest six platform packages")
	}
	for _, t := range distributionTargets04511(version) {
		r, ok := a.Targets[t.target]
		if !ok || r.Name != t.packageFile || !hex64.MatchString(r.SHA256) {
			return fmt.Errorf("operations GA target missing: %s", t.target)
		}
		h, e := distributionHash04511(dir, t.packageFile)
		if e != nil {
			return e
		}
		if h != r.SHA256 {
			return fmt.Errorf("operations GA final package changed: %s", t.target)
		}
	}
	for _, name := range []string{operationsGAFile0460, operationsGASig0460} {
		required := false
		artifact := false
		for _, r := range m.RequiredFiles {
			if r == name {
				required = true
			}
		}
		for _, f := range m.Artifacts {
			if f.Name == name && f.Required && f.Status == "present" {
				h, _, e := hashFile(filepath.Join(dir, name))
				if e == nil && h == f.SHA256 {
					artifact = true
				}
			}
		}
		if !required || !artifact {
			return fmt.Errorf("operations GA not bound into signed release manifest: %s", name)
		}
	}
	return nil
}
