package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// The CLI runs probes IN THE OPERATOR'S ALREADY-ISOLATED staging environment.
// This is intentionally not an arbitrary remote command-execution endpoint.
// No server-provided command is executed, and no shell is involved.
type rehearsalPlayer03310 struct {
	SourceID          string `json:"sourceId"`
	UUID              string `json:"uuid"`
	InventorySHA256   string `json:"inventorySha256"`
	PermissionsSHA256 string `json:"permissionsSha256"`
	Economy           string `json:"economy"`
	SkinSHA256        string `json:"skinSha256"`
	Admin             bool   `json:"admin"`
}
type rehearsalSnapshot03310 struct {
	WorldSHA256          string                 `json:"worldSha256"`
	Loader               string                 `json:"loader"`
	OptionalPresetSHA256 string                 `json:"optionalPresetSha256"`
	Players              []rehearsalPlayer03310 `json:"players"`
}
type rehearsalProbe03310 struct {
	Name           string `json:"name"`
	Passed         bool   `json:"passed"`
	RunID          string `json:"runId"`
	StageID        string `json:"stageId"`
	UUID           string `json:"uuid,omitempty"`
	EvidenceSHA256 string `json:"evidenceSha256"`
	Detail         string `json:"detail,omitempty"`
}
type rehearsalReport03310 struct {
	Format                string                 `json:"format"`
	RunID                 string                 `json:"runId"`
	StageID               string                 `json:"stageId"`
	SourceInventorySHA256 string                 `json:"sourceInventorySha256"`
	SourceSnapshotSHA256  string                 `json:"sourceSnapshotSha256"`
	TargetSnapshotSHA256  string                 `json:"targetSnapshotSha256"`
	Source                rehearsalSnapshot03310 `json:"source"`
	Target                rehearsalSnapshot03310 `json:"target"`
	Probes                []rehearsalProbe03310  `json:"probes"`
	Blockers              []string               `json:"blockers"`
	Ready                 bool                   `json:"ready"`
	CutoverAllowed        bool                   `json:"cutoverAllowed"`
}

var rehearsalRequired03310 = []string{"launch", "login", "join", "skins", "loader", "optional", "admin"}
var rehearsalHex03310 = regexp.MustCompile(`^[a-f0-9]{64}$`)
var rehearsalStageID03310 = regexp.MustCompile(`^[a-zA-Z0-9_-]{16,128}$`)

func rehearsalPath03310(root, sub string) (string, error) {
	if filepath.IsAbs(sub) || strings.ContainsAny(sub, "\\\x00") || sub == "" {
		return "", errors.New("expected relative staging path")
	}
	full := filepath.Join(root, sub)
	rel, e := filepath.Rel(root, full)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", errors.New("path escapes staging root")
	}
	real, e := filepath.EvalSymlinks(full)
	if e != nil {
		return "", e
	}
	rel, e = filepath.Rel(root, real)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", errors.New("symlink escapes staging root")
	}
	return real, nil
}
func rehearsalRead03310(root, sub string, limit int64) ([]byte, error) {
	path, e := rehearsalPath03310(root, sub)
	if e != nil {
		return nil, e
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Size() == 0 || st.Size() > limit {
		return nil, errors.New("invalid staging evidence file size")
	}
	return io.ReadAll(io.LimitReader(f, limit+1))
}
func rehearsalDigest03310(v any) (string, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func rehearsalProbeExec03310(ctx context.Context, root, run, stage, name string) (rehearsalProbe03310, error) {
	probe := rehearsalProbe03310{Name: name, RunID: run, StageID: stage}
	program, e := rehearsalPath03310(root, "probes/"+name)
	if e != nil {
		return probe, e
	}
	st, e := os.Stat(program)
	if e != nil {
		return probe, e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
		return probe, errors.New("probe must be executable regular file")
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program)
	cmd.Dir = root
	// Inherit no tokens, no cloud credentials, no production DB connection.
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + root, "MIGRATION_RUN_ID=" + run, "MIGRATION_STAGE_ID=" + stage, "MIGRATION_CHECK=" + name}
	var stdout, stderr limitedProbeBuffer03310
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if e = cmd.Run(); e != nil {
		return probe, fmt.Errorf("probe %s failed (exit/timeout): %w", name, e)
	}
	var output struct {
		Passed   bool   `json:"passed"`
		UUID     string `json:"uuid"`
		Evidence string `json:"evidenceFile"`
		Detail   string `json:"detail"`
	}
	dec := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	dec.DisallowUnknownFields()
	if e = dec.Decode(&output); e != nil {
		return probe, fmt.Errorf("invalid %s JSON: %w", name, e)
	}
	var trailing any
	if dec.Decode(&trailing) != io.EOF {
		return probe, errors.New("probe JSON has trailing data")
	}
	if output.Evidence == "" || len(output.Detail) > 512 {
		return probe, errors.New("probe must produce bounded evidence file and detail")
	}
	raw, e := rehearsalRead03310(root, output.Evidence, 1<<20)
	if e != nil {
		return probe, fmt.Errorf("probe %s missing evidence: %w", name, e)
	}
	h := sha256.Sum256(raw)
	probe.Passed = output.Passed
	probe.UUID = output.UUID
	probe.Detail = ""
	probe.EvidenceSHA256 = hex.EncodeToString(h[:])
	return probe, nil
}

// Prevent external test processes from filling server/CLI RAM or leaking stderr.
type limitedProbeBuffer03310 struct{ bytes.Buffer }

func (b *limitedProbeBuffer03310) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 16<<10 {
		return 0, errors.New("probe output exceeds 16 KiB")
	}
	return b.Buffer.Write(p)
}

func migrationRehearsalRun03310(ctx context.Context, root, run, inventory string) (rehearsalReport03310, error) {
	var report rehearsalReport03310
	if !rehearsalHex03310.MatchString(inventory) || len(run) < 8 || len(run) > 128 {
		return report, errors.New("--run and exact --inventory-sha256 required")
	}
	if !filepath.IsAbs(root) {
		return report, errors.New("--stage must be an absolute path to a separate sandbox")
	}
	real, e := filepath.EvalSymlinks(root)
	if e != nil {
		return report, e
	}
	if real == "/" || real == filepath.Dir(real) {
		return report, errors.New("unsafe staging root")
	}
	marker, e := rehearsalRead03310(real, ".migration-stage.json", 8192)
	if e != nil {
		return report, e
	}
	var stage struct {
		Format   string `json:"format"`
		RunID    string `json:"runId"`
		StageID  string `json:"stageId"`
		Isolated bool   `json:"isolated"`
	}
	if e = json.Unmarshal(marker, &stage); e != nil {
		return report, e
	}
	if stage.Format != "never/migration-stage/v1" || stage.RunID != run || !rehearsalStageID03310.MatchString(stage.StageID) || !stage.Isolated {
		return report, errors.New("invalid isolated staging marker")
	}
	a, e := rehearsalRead03310(real, "source-snapshot.json", 4<<20)
	if e != nil {
		return report, e
	}
	report.Format = "never/gravit-rehearsal/v1"
	report.RunID = run
	report.StageID = stage.StageID
	report.SourceInventorySHA256 = inventory
	if e = json.Unmarshal(a, &report.Source); e != nil {
		return report, e
	}
	report.SourceSnapshotSHA256, e = rehearsalDigest03310(report.Source)
	if e != nil {
		return report, e
	}
	report.Probes = []rehearsalProbe03310{}
	for _, check := range rehearsalRequired03310 {
		probe, err := rehearsalProbeExec03310(ctx, real, run, stage.StageID, check)
		if err != nil {
			return report, err
		} // No report submitted after failed execution.
		report.Probes = append(report.Probes, probe)
	}
	// Read the final target snapshot AFTER probes so tests that modify the
	// isolated world cannot pass by supplying a stale pre-launch snapshot.
	b, e := rehearsalRead03310(real, "target-snapshot.json", 4<<20)
	if e != nil {
		return report, e
	}
	if e = json.Unmarshal(b, &report.Target); e != nil {
		return report, e
	}
	report.TargetSnapshotSHA256, e = rehearsalDigest03310(report.Target)
	if e != nil {
		return report, e
	}
	// The backend recomputes all data comparisons, probes and prerequisites in
	// the DB. Locally never claim a successful certification until it responds.
	report.Ready = false
	report.CutoverAllowed = false
	report.Blockers = []string{"pending server-side authoritative verification"}
	return report, nil
}
func handleMigrationRehearsal03310(args []string) error {
	run := flagValue(args, "--run", "")
	stage := flagValue(args, "--stage", "")
	inventory := flagValue(args, "--inventory-sha256", "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	report, e := migrationRehearsalRun03310(ctx, stage, run, inventory)
	if e != nil {
		return e
	}
	backend := strings.TrimRight(flagValue(args, "--backend", ""), "/")
	token := backendToken(args)
	if backend == "" || token == "" {
		return errors.New("--backend and --token required: local results are not yet certified")
	}
	endpoint := backend + "/api/v1/admin/migration-runs/" + run + "/rehearsal"
	if e = migrationModuleEndpoint0338(endpoint); e != nil {
		return e
	}
	raw, e := json.Marshal(report)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(raw))
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Migration-Rehearsal-Confirm", run)
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := client.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	answer, e := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if e != nil {
		return e
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("rehearsal commit HTTP %d: %s", resp.StatusCode, answer)
	}
	var parsed any
	if e = json.Unmarshal(answer, &parsed); e != nil {
		return e
	}
	out := flagValue(args, "--output", "")
	if out != "" {
		return writePrivateIdentityReport0334(out, parsed)
	}
	fmt.Println(string(answer))
	return nil
}
