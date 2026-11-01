// Package gravitplan builds a reproducible, read-only Gravit migration preview
// from the same verified sources and converters used by the import operations.
package gravitplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	gc "gitflic.ru/skif4er/launcher/services/api/internal/gravitcontent"
	gd "gitflic.ru/skif4er/launcher/services/api/internal/gravitdetector"
	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
	gm "gitflic.ru/skif4er/launcher/services/api/internal/gravitmodules"
)

const Format = "launcher.gravit-migration-plan.v1"

type Destination struct {
	ProfilePath string `json:"profilePath"`
	ProfileID   string `json:"profileId"`
	ProfileName string `json:"profileName"`
	Loader      string `json:"loader"`
	Channel     string `json:"channel"`
	Version     string `json:"version"`
}
type Item struct {
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Target string `json:"target,omitempty"`
	Status string `json:"status"` // automatic, transformed, manual, blocked, excluded
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// IdentityPreview includes only counts and diagnostic reasons. Passwords,
// usernames, UUIDs and tokens are never persisted in a migration plan.
type IdentityPreview struct {
	SourceAccounts         int    `json:"sourceAccounts"`
	DuplicateOrConflicting int    `json:"duplicateOrConflicting"`
	State                  string `json:"state"` // review_required | blocked
	Reason                 string `json:"reason,omitempty"`
}
type Checklist struct {
	Action   string `json:"action"`
	Detail   string `json:"detail"`
	Required bool   `json:"required"`
}
type Plan struct {
	Format          string          `json:"format"`
	RunID           string          `json:"runId"`
	ProjectID       string          `json:"projectId"`
	SourceSHA256    string          `json:"sourceSha256"`
	InventorySHA256 string          `json:"inventorySha256"`
	TargetSHA256    string          `json:"targetSha256"`
	Destination     Destination     `json:"destination"`
	DetectedVersion string          `json:"detectedVersion,omitempty"`
	Items           []Item          `json:"items"`
	Checklist       []Checklist     `json:"checklist"`
	Counts          map[string]int  `json:"counts"`
	TransferBytes   int64           `json:"transferBytes"`
	Blockers        []string        `json:"blockers"`
	Status          string          `json:"status"` // blocked or manual; NEVER means approved to cutover
	Content         gc.Plan         `json:"content"`
	Modules         gm.Report       `json:"modules"`
	Identities      IdentityPreview `json:"identities"`
	PlanSHA256      string          `json:"planSha256"`
}

func Digest(p Plan) (string, error) {
	p.PlanSHA256 = ""
	b, e := json.Marshal(p)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func Verify(p Plan) error {
	if p.Format != Format || len(p.PlanSHA256) != 64 {
		return errors.New("invalid migration plan format or digest")
	}
	d, e := Digest(p)
	if e != nil {
		return e
	}
	if d != p.PlanSHA256 {
		return errors.New("migration plan checksum mismatch")
	}
	return nil
}
func Build(runID, projectID, targetSHA string, d Destination, v inv.Inventory, c gd.Report, m gm.Report, content gc.Plan, targetProfileExists bool, identities IdentityPreview) (Plan, error) {
	if runID == "" || projectID == "" || len(targetSHA) != 64 || v.Format != inv.Format || c.Format != "launcher.gravit-compatibility.v1" || m.Format != gm.Format || v.SourceSHA256 != c.SourceSHA256 || v.SourceSHA256 != m.SourceSHA256 || v.ManifestSHA256 != m.InventorySHA256 || content.SourceSHA256 != v.SourceSHA256 || content.InventorySHA256 != v.ManifestSHA256 || content.ProfilePath != d.ProfilePath || content.Profile.Profile.ID != d.ProfileID || content.Profile.Profile.ProjectID != projectID {
		return Plan{}, errors.New("source, target or content preview mismatch")
	}
	if _, e := v.Manifest(); e != nil {
		return Plan{}, e
	}
	p := Plan{Format: Format, RunID: runID, ProjectID: projectID, SourceSHA256: v.SourceSHA256, InventorySHA256: v.ManifestSHA256, TargetSHA256: targetSHA, Destination: d, DetectedVersion: c.DetectedVersion, Items: []Item{}, Checklist: []Checklist{}, Counts: map[string]int{"automatic": 0, "transformed": 0, "manual": 0, "blocked": 0, "excluded": 0}, Blockers: []string{}, Content: content, Modules: m, Identities: identities, Status: "manual"}
	add := func(item Item) {
		p.Items = append(p.Items, item)
		p.Counts[item.Status]++
		if item.Status == "automatic" || item.Status == "transformed" {
			p.TransferBytes += item.Bytes
		}
		if item.Status == "blocked" {
			p.Blockers = append(p.Blockers, fmt.Sprintf("%s: %s", item.Source, item.Reason))
		}
	}
	transferred := map[string]gc.File{}
	for _, f := range content.Files {
		transferred[f.SourcePath] = f
	}
	for _, f := range v.Files {
		row := Item{Kind: f.Kind, Source: f.Path, Bytes: f.Size, SHA256: f.SHA256, Status: "manual"}
		switch f.Kind {
		case "client_profile":
			if f.Path == d.ProfilePath {
				row.Status = "transformed"
				row.Target = d.ProfileID
				row.Reason = "profile settings converted using active content converter; release build and game launch still required"
			} else {
				row.Reason = "profile not selected: configure and preview each profile before cutover"
			}
		case "asset", "client", "library":
			if t, ok := transferred[f.Path]; ok {
				row.Status = "automatic"
				row.Target = t.TargetPath
				row.Reason = "file SHA-256 pinned to source inventory"
			} else {
				row.Reason = "file not included in selected profile; inspect ownership and import separately"
			}
		case "module", "module_config", "server_wrapper":
			row.Reason = "review module replacement or ServerBridge enrollment; no foreign JAR is executed"
		case "authentication":
			row.Reason = "identity, UUID and password verifier mapping requires a separate verified preview"
		case "texture":
			row.Reason = "texture requires validated source/provider import and Minecraft rendering check"
		case "key":
			row.Status = "excluded"
			row.Reason = "legacy private keys and trust credentials must never be imported; rotate on target"
		case "launchserver", "runtime":
			row.Reason = "settings must be configured and validated in Never; no secrets automatically carried over"
		default:
			row.Reason = "unclassified source; operator must decide before cutover"
		}
		add(row)
	}
	for _, f := range c.Findings {
		if f.Severity == "blocked" {
			p.Blockers = append(p.Blockers, fmt.Sprintf("compatibility %s (%s): %s", f.Code, f.Path, f.Message))
		}
	}
	for _, f := range m.Modules {
		if f.Status == "blocked" {
			p.Blockers = append(p.Blockers, "module "+f.Path+": "+f.Reason)
		}
	}
	for _, w := range m.Wrappers {
		if w.Status == "blocked" {
			p.Blockers = append(p.Blockers, "wrapper "+w.Path+": "+w.Reason)
		}
	}
	for _, b := range m.Blockers {
		p.Blockers = append(p.Blockers, "modules: "+b)
	}
	for _, b := range content.Blockers {
		p.Blockers = append(p.Blockers, "content: "+b)
	}
	if !content.Ready {
		p.Blockers = append(p.Blockers, "selected profile cannot be imported with the current converter")
	}
	if identities.State != "review_required" || identities.DuplicateOrConflicting > 0 || identities.SourceAccounts == 0 {
		p.Blockers = append(p.Blockers, "identities: "+identities.Reason)
	}
	if targetProfileExists {
		p.Blockers = append(p.Blockers, "destination profile ID already exists; select a new profile ID or reconcile explicitly")
	}
	if c.Status == "blocked" || c.VersionStatus == "unsupported" || c.VersionStatus == "conflict" {
		p.Blockers = append(p.Blockers, "Gravit compatibility analysis is blocked")
	}
	if len(p.Blockers) > 0 {
		p.Status = "blocked"
	}
	p.Checklist = []Checklist{
		{"verify_source", "Re-upload the original ZIP at import; source SHA-256 and manifest must still match", true},
		{"resolve_manual", "Review unselected profiles, unknown files, optional conditions and module replacements", true},
		{"verify_uuid", "Reconcile every account UUID with playerdata, permissions and inventory; handle conflicting UUIDs manually", true},
		{"reset_credentials", "Rotate launcher, device, ServerBridge and proxy keys; plan resets for unsupported password hashes", true},
		{"textures", "Re-import validated skins/capes and confirm rendering for the selected authentication mode", true},
		{"rehearse", "Build a signed target release and prove real client launch, server join and data continuity", true},
		{"backup_and_rollback", "Take and restore-test source/world backups; agree on downtime, writer fencing and rollback point", true},
	}
	sort.Slice(p.Items, func(i, j int) bool { return p.Items[i].Source < p.Items[j].Source })
	sort.Strings(p.Blockers)
	p.Blockers = unique(p.Blockers)
	digest, e := Digest(p)
	if e != nil {
		return Plan{}, e
	}
	p.PlanSHA256 = digest
	return p, nil
}
func unique(values []string) []string {
	o := values[:0]
	for _, v := range values {
		if len(o) == 0 || o[len(o)-1] != v {
			o = append(o, v)
		}
	}
	return o
}
