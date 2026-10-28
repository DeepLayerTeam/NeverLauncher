// Package gravitreports provides deterministic, fail-closed Migration Center
// certification reports derived from committed database receipts. No password,
// bearer token, device key or source configuration is included.
package gravitreports

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

const Format = "neverlauncher.gravit-migration-report.v1"

type Item struct {
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Target string `json:"target,omitempty"`
	Status string `json:"status"` // transferred, transformed, manual, blocked
	SHA256 string `json:"sha256,omitempty"`
	Reason string `json:"reason,omitempty"`
}
type Identity struct {
	Provider     string `json:"provider"`
	SourceID     string `json:"sourceId"`
	Username     string `json:"username"`
	UUID         string `json:"uuid"`
	TargetUserID string `json:"targetUserId,omitempty"`
	Status       string `json:"status"`
}
type Evidence struct {
	Stage   string `json:"stage"`
	SHA256  string `json:"sha256,omitempty"`
	State   string `json:"state"`
	Details string `json:"details,omitempty"`
}
type Decision struct {
	Sequence int64  `json:"sequence"`
	Kind     string `json:"kind"`
	Revision int64  `json:"revision"`
}
type Report struct {
	Format          string         `json:"format"`
	RunID           string         `json:"runId"`
	ProjectID       string         `json:"projectId"`
	SourceSHA256    string         `json:"sourceSha256,omitempty"`
	InventorySHA256 string         `json:"inventorySha256,omitempty"`
	RunRevision     int64          `json:"runRevision"`
	Items           []Item         `json:"items"`
	Identities      []Identity     `json:"identities"`
	Evidence        []Evidence     `json:"evidence"`
	Decisions       []Decision     `json:"operatorDecisions"`
	Counts          map[string]int `json:"counts"`
	Blockers        []string       `json:"blockers"`
	Status          string         `json:"status"` // blocked, review_required, rc_candidate (NEVER GA certified)
	ReportSHA256    string         `json:"reportSha256"`
}

func validDigest(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, b := range []byte(v) {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}
func Digest(v Report) (string, error) {
	v.ReportSHA256 = ""
	b, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func Verify(v Report) error {
	if v.Format != Format || v.RunID == "" || v.ProjectID == "" || !validDigest(v.ReportSHA256) {
		return errors.New("invalid migration report")
	}
	expected, e := Digest(v)
	if e != nil {
		return e
	}
	if expected != v.ReportSHA256 {
		return errors.New("migration report digest mismatch")
	}
	return nil
}

// Finalize recomputes every readiness and count field, ignoring the caller's
// decision. It makes missing evidence explicit, rather than treating empty
// source data as compatible or a historical manual acknowledgment as proof.
func Finalize(v Report) (Report, error) {
	if v.RunID == "" || v.ProjectID == "" {
		return Report{}, errors.New("missing migration scope")
	}
	v.Format = Format
	v.ReportSHA256 = ""
	v.Status = "blocked"
	v.Counts = map[string]int{"transferred": 0, "transformed": 0, "manual": 0, "blocked": 0}
	if v.Items == nil {
		v.Items = []Item{}
	}
	if v.Identities == nil {
		v.Identities = []Identity{}
	}
	if v.Evidence == nil {
		v.Evidence = []Evidence{}
	}
	if v.Decisions == nil {
		v.Decisions = []Decision{}
	}
	if v.Blockers == nil {
		v.Blockers = []string{}
	}
	seenItem := map[string]bool{}
	for _, item := range v.Items {
		if item.Kind == "" || item.Source == "" {
			return Report{}, errors.New("invalid inventory item")
		}
		if item.SHA256 != "" && !validDigest(item.SHA256) {
			return Report{}, errors.New("invalid inventory checksum")
		}
		if item.Status != "transferred" && item.Status != "transformed" && item.Status != "manual" && item.Status != "blocked" {
			return Report{}, fmt.Errorf("invalid item status %q", item.Status)
		}
		k := item.Kind + "\x00" + item.Source + "\x00" + item.Target
		if seenItem[k] {
			return Report{}, errors.New("duplicate report item")
		}
		seenItem[k] = true
		v.Counts[item.Status]++
	}
	sort.Slice(v.Items, func(i, j int) bool {
		a, b := v.Items[i], v.Items[j]
		return a.Kind+"\x00"+a.Source+"\x00"+a.Target < b.Kind+"\x00"+b.Source+"\x00"+b.Target
	})
	seenUUID := map[string]string{}
	seenIdentity := map[string]bool{}
	for _, a := range v.Identities {
		k := a.Provider + "\x00" + a.SourceID
		if a.Provider == "" || a.SourceID == "" || !validIdentityUUID(a.UUID) || seenIdentity[k] {
			return Report{}, errors.New("invalid/duplicate identity in report")
		}
		seenIdentity[k] = true
		if other, ok := seenUUID[a.UUID]; ok && other != k {
			v.Blockers = append(v.Blockers, "identity UUID collision: "+a.UUID)
		}
		seenUUID[a.UUID] = k
		if a.Status != "matched" && a.Status != "imported" {
			v.Blockers = append(v.Blockers, "identity not resolved: "+a.Provider+"/"+a.SourceID)
		}
		if a.TargetUserID == "" {
			v.Blockers = append(v.Blockers, "identity has no Never user: "+a.Provider+"/"+a.SourceID)
		}
	}
	sort.Slice(v.Identities, func(i, j int) bool {
		a, b := v.Identities[i], v.Identities[j]
		return a.Provider+"\x00"+a.SourceID < b.Provider+"\x00"+b.SourceID
	})
	required := []string{"compatibility", "inventory", "identity", "authentication", "security", "content", "modules", "rehearsal", "cutover", "rollback"}
	stages := map[string]string{}
	for _, ev := range v.Evidence {
		if ev.Stage == "" {
			return Report{}, errors.New("invalid evidence stage")
		}
		if _, ok := stages[ev.Stage]; ok {
			return Report{}, errors.New("duplicate evidence stage")
		}
		// Never interpret a new/unrecognized state as a successful check.
		switch ev.State {
		case "verified", "missing", "blocked", "manual":
		default:
			return Report{}, fmt.Errorf("unknown evidence state %q", ev.State)
		}
		stages[ev.Stage] = ev.State
		if ev.SHA256 != "" && !validDigest(ev.SHA256) {
			return Report{}, errors.New("invalid evidence checksum")
		}
		if ev.State == "missing" || ev.State == "blocked" ||
			(ev.State == "manual" && (ev.Stage == "cutover" || ev.Stage == "rollback" ||
				len(ev.Stage) > len("cutover_scope:") && ev.Stage[:len("cutover_scope:")] == "cutover_scope:")) {
			v.Blockers = append(v.Blockers, ev.Stage+": "+ev.State+" "+ev.Details)
		}
	}
	for _, stage := range required {
		if stages[stage] != "verified" {
			v.Blockers = append(v.Blockers, stage+": required stage not verified")
		}
	}
	if !validDigest(v.SourceSHA256) || !validDigest(v.InventorySHA256) {
		v.Blockers = append(v.Blockers, "unverified source/inventory digests")
	}
	if len(v.Identities) == 0 {
		v.Blockers = append(v.Blockers, "no verified player identities")
	}
	if v.Counts["blocked"] > 0 {
		v.Blockers = append(v.Blockers, "inventory contains blocked components")
	}
	sort.Slice(v.Evidence, func(i, j int) bool { return v.Evidence[i].Stage < v.Evidence[j].Stage })
	sort.Slice(v.Decisions, func(i, j int) bool { return v.Decisions[i].Sequence < v.Decisions[j].Sequence })
	sort.Strings(v.Blockers)
	// Duplicate identical messages are not useful and shouldn't change digest.
	uniq := v.Blockers[:0]
	for _, s := range v.Blockers {
		if len(uniq) == 0 || uniq[len(uniq)-1] != s {
			uniq = append(uniq, s)
		}
	}
	v.Blockers = uniq
	if len(v.Blockers) == 0 {
		v.Status = "review_required"
	} // no automatic production certification, ever
	digest, e := Digest(v)
	if e != nil {
		return Report{}, e
	}
	v.ReportSHA256 = digest
	return v, nil
}
func validIdentityUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, b := range []byte(s) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if b != '-' {
				return false
			}
			continue
		}
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}
