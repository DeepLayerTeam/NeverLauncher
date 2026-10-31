package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const rehearsalReceipt0365 = "RELEASE_REHEARSAL_0365.json"

func rehearsalRequired0365(v string) bool {
	triple, ok := parseVersionTriple0158(v)
	return ok && compareVersionTriple0158(triple, [3]int{0, 36, 5}) >= 0
}

type rehearsalTarget0365 struct {
	Target         string `json:"target"`
	Binary         string `json:"binary"`
	BinarySHA      string `json:"binarySha256"`
	Package        string `json:"package"`
	PackageSHA     string `json:"packageSha256"`
	PackageMembers int    `json:"packageMembers"`
}

type rehearsalReceiptData0365 struct {
	SchemaVersion string                `json:"schemaVersion"`
	Version       string                `json:"version"`
	Commit        string                `json:"commit"`
	RunID         string                `json:"runId"`
	RunAttempt    string                `json:"runAttempt"`
	Status        string                `json:"status"`
	ApprovalSHA   string                `json:"gaApprovalSha256"`
	Targets       []rehearsalTarget0365 `json:"targets"`
}

// The independent Ed25519 GA gate is also verified by the release signer.
// Check that its package-inspection receipt is complete, current and included
// in the checksums that are about to be release-signed.
func verifyRehearsal0365(dir, version, commit string) error {
	if !rehearsalRequired0365(version) {
		return nil
	}
	path := filepath.Join(dir, rehearsalReceipt0365)
	stat, err := os.Lstat(path)
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > 1<<20 {
		return errors.New("0.36.5+: missing/unsafe final-package rehearsal receipt")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := gaUniqueJSON0361(raw); err != nil {
		return err
	}
	var r rehearsalReceiptData0365
	if err = json.Unmarshal(raw, &r); err != nil {
		return err
	}
	if r.SchemaVersion != "launcher.release.rehearsal.v1" || r.Version != version ||
		r.Commit != commit || r.Status != "package-and-ga-verified" || len(r.Targets) != 6 {
		return errors.New("0.36.5+: stale/incomplete release rehearsal")
	}
	runID := strings.TrimSpace(os.Getenv("LAUNCHER_RELEASE_RUN_ID"))
	if runID == "" {
		runID = strings.TrimSpace(os.Getenv("GITHUB_RUN_ID"))
	}
	attempt := strings.TrimSpace(os.Getenv("LAUNCHER_RELEASE_RUN_ATTEMPT"))
	if attempt == "" {
		attempt = strings.TrimSpace(os.Getenv("GITHUB_RUN_ATTEMPT"))
	}
	if runID == "" || attempt == "" || r.RunID != runID || r.RunAttempt != attempt {
		return errors.New("0.36.5+: rehearsal belongs to a different CI run/attempt")
	}
	gaRaw, err := os.ReadFile(filepath.Join(dir, "GA_VERIFIED_TARGETS.json"))
	if err != nil {
		return err
	}
	var ga struct {
		ApprovalSHA string `json:"approvalSha256"`
		Targets     []struct {
			Target     string `json:"target"`
			BinarySHA  string `json:"binarySha256"`
			PackageSHA string `json:"packageSha256"`
		} `json:"targets"`
	}
	if err = json.Unmarshal(gaRaw, &ga); err != nil {
		return err
	}
	if r.ApprovalSHA == "" || r.ApprovalSHA != ga.ApprovalSHA || len(ga.Targets) != 6 {
		return errors.New("0.36.5+: release rehearsal signed approval does not match GA receipt")
	}
	seen := map[string]bool{}
	for _, item := range r.Targets {
		if seen[item.Target] || item.PackageMembers < 4 {
			return errors.New("0.36.5+: duplicate/incomplete platform package")
		}
		seen[item.Target] = true
		binary, pack := gaTargetPaths0361(version, item.Target)
		if binary == "" || item.Binary != binary || item.Package != pack {
			return fmt.Errorf("0.36.5+: unapproved platform %q", item.Target)
		}
		for _, entry := range []struct{ file, digest string }{{binary, item.BinarySHA}, {pack, item.PackageSHA}} {
			actual, _, err := hashFile(filepath.Join(dir, entry.file))
			if err != nil || !strings.EqualFold(actual, entry.digest) {
				return fmt.Errorf("0.36.5+: changed release bytes: %s", entry.file)
			}
		}
		matched := false
		for _, g := range ga.Targets {
			if g.Target == item.Target && g.BinarySHA == item.BinarySHA && g.PackageSHA == item.PackageSHA {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("0.36.5+: GA approval mismatch: %s", item.Target)
		}
	}
	if len(seen) != 6 {
		return errors.New("0.36.5+: missing mandatory target")
	}
	sums, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	target := hex.EncodeToString(digest[:])
	matches := 0
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == rehearsalReceipt0365 {
			if fields[0] != target {
				return errors.New("0.36.5+: unsigned/stale rehearsal digest")
			}
			matches++
		}
	}
	if matches != 1 {
		return errors.New("0.36.5+: rehearsal omitted/duplicated in signed SHA256SUMS")
	}
	return nil
}
