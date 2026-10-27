// Package gravitrehearsal validates the evidence produced by an isolated,
// operator-owned Gravit -> Never test deployment. It never runs on production
// resources and never treats unexecuted tests as passing.
package gravitrehearsal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const Format = "never/gravit-rehearsal/v1"
const MaxReportBytes = 8 << 20

var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var economyAmount = regexp.MustCompile(`^-?[0-9]+(?:\.[0-9]{1,6})?$`)
var validUUID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

// Player is a point-in-time fixture read from the *source* and from the
// isolated test environment. Digests are generated from actual data exports,
// not arbitrary pass/fail flags. Economy is decimal text to avoid float loss.
type Player struct {
	SourceID          string `json:"sourceId"`
	UUID              string `json:"uuid"`
	InventorySHA256   string `json:"inventorySha256"`
	PermissionsSHA256 string `json:"permissionsSha256"`
	Economy           string `json:"economy"`
	SkinSHA256        string `json:"skinSha256"`
	Admin             bool   `json:"admin"`
}
type Snapshot struct {
	WorldSHA256          string   `json:"worldSha256"`
	Loader               string   `json:"loader"`
	OptionalPresetSHA256 string   `json:"optionalPresetSha256"`
	Players              []Player `json:"players"`
}
type Probe struct {
	Name           string `json:"name"`
	Passed         bool   `json:"passed"`
	RunID          string `json:"runId"`
	StageID        string `json:"stageId"`
	UUID           string `json:"uuid,omitempty"`
	EvidenceSHA256 string `json:"evidenceSha256"`
	Detail         string `json:"detail,omitempty"`
}
type Report struct {
	Format                string   `json:"format"`
	RunID                 string   `json:"runId"`
	StageID               string   `json:"stageId"`
	SourceInventorySHA256 string   `json:"sourceInventorySha256"`
	SourceSnapshotSHA256  string   `json:"sourceSnapshotSha256"`
	TargetSnapshotSHA256  string   `json:"targetSnapshotSha256"`
	Source                Snapshot `json:"source"`
	Target                Snapshot `json:"target"`
	Probes                []Probe  `json:"probes"`
	Blockers              []string `json:"blockers"`
	Ready                 bool     `json:"ready"`
	// Cutover remains unauthorized until MIG11; a rehearsal is not a cutover.
	CutoverAllowed bool `json:"cutoverAllowed"`
}

var RequiredProbes = []string{"launch", "login", "join", "skins", "loader", "optional", "admin"}

func SnapshotDigest(v Snapshot) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// Evaluate independently recomputes readiness. The backend MUST use this
// function on submitted evidence, not accept client-supplied Ready or Blockers.
func Evaluate(v Report) (Report, error) {
	if v.Format != Format || len(v.RunID) < 8 || len(v.RunID) > 128 || len(v.StageID) < 16 || len(v.StageID) > 128 || !digest.MatchString(v.SourceInventorySHA256) {
		return Report{}, errors.New("invalid run/stage/inventory binding")
	}
	src, e := SnapshotDigest(v.Source)
	if e != nil {
		return Report{}, e
	}
	dst, e := SnapshotDigest(v.Target)
	if e != nil {
		return Report{}, e
	}
	if v.SourceSnapshotSHA256 != src || v.TargetSnapshotSHA256 != dst {
		return Report{}, errors.New("snapshot digest mismatch")
	}
	blocks := []string{}
	add := func(s string) { blocks = append(blocks, s) }
	if !digest.MatchString(v.Source.WorldSHA256) || !digest.MatchString(v.Target.WorldSHA256) || v.Source.WorldSHA256 != v.Target.WorldSHA256 {
		add("world snapshot checksum differs")
	}
	if v.Source.Loader == "" || v.Source.Loader != v.Target.Loader {
		add("Minecraft loader mismatch")
	}
	if !digest.MatchString(v.Source.OptionalPresetSHA256) || v.Source.OptionalPresetSHA256 != v.Target.OptionalPresetSHA256 {
		add("optional preset differs")
	}
	if len(v.Source.Players) == 0 || len(v.Source.Players) > 20000 || len(v.Target.Players) > 20000 {
		return Report{}, errors.New("unsupported rehearsal population")
	}
	indexed := map[string]Player{}
	for _, p := range v.Source.Players {
		if p.SourceID == "" || !validUUID.MatchString(p.UUID) || !digest.MatchString(p.InventorySHA256) || !digest.MatchString(p.PermissionsSHA256) || !digest.MatchString(p.SkinSHA256) || !economyAmount.MatchString(p.Economy) {
			return Report{}, errors.New("invalid source player")
		}
		if _, ok := indexed[p.SourceID]; ok {
			return Report{}, errors.New("duplicate source identity")
		}
		indexed[p.SourceID] = p
	}
	seen := map[string]bool{}
	uuidSeen := map[string]bool{}
	for _, p := range v.Target.Players {
		if seen[p.SourceID] || uuidSeen[p.UUID] {
			return Report{}, errors.New("duplicate target identity/UUID")
		}
		seen[p.SourceID] = true
		uuidSeen[p.UUID] = true
		before, ok := indexed[p.SourceID]
		if !ok {
			add("unexpected target identity")
			continue
		}
		if p.UUID != before.UUID {
			add("UUID differs: " + p.SourceID)
		}
		if p.InventorySHA256 != before.InventorySHA256 {
			add("inventory differs: " + p.SourceID)
		}
		if p.PermissionsSHA256 != before.PermissionsSHA256 {
			add("permissions differ: " + p.SourceID)
		}
		if p.Economy != before.Economy {
			add("economy differs: " + p.SourceID)
		}
		if p.SkinSHA256 != before.SkinSHA256 {
			add("skin differs: " + p.SourceID)
		}
		if p.Admin != before.Admin {
			add("admin privileges differ: " + p.SourceID)
		}
	}
	for id := range indexed {
		if !seen[id] {
			add("missing player: " + id)
		}
	}
	if len(v.Probes) > 32 {
		return Report{}, errors.New("too many probes")
	}
	results := map[string]bool{}
	for _, p := range v.Probes {
		if p.RunID != v.RunID || p.StageID != v.StageID || p.Detail != "" || !digest.MatchString(p.EvidenceSHA256) {
			return Report{}, errors.New("invalid probe evidence binding")
		}
		if _, ok := results[p.Name]; ok {
			return Report{}, errors.New("duplicate probe")
		}
		results[p.Name] = true
		if !p.Passed {
			add("probe failed: " + p.Name)
		}
		if (p.Name == "login" || p.Name == "join") && !uuidSeen[p.UUID] {
			add("probe returned unknown UUID: " + p.Name)
		}
	}
	for _, name := range RequiredProbes {
		if !results[name] {
			add("required probe missing: " + name)
		}
	}
	sort.Strings(blocks)
	v.Blockers = blocks
	v.Ready = len(blocks) == 0
	v.CutoverAllowed = false
	return v, nil
}
func CompareReady(v Report) error {
	check, err := Evaluate(v)
	if err != nil {
		return err
	}
	a, _ := json.Marshal(check.Blockers)
	b, _ := json.Marshal(v.Blockers)
	if string(a) != string(b) || check.Ready != v.Ready || v.CutoverAllowed {
		return fmt.Errorf("rehearsal status is not verified: %s", strings.Join(check.Blockers, "; "))
	}
	return nil
}
