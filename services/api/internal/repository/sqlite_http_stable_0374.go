package repository

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

// The token itself is never written to SQLite or to a durable job. Consuming
// this row and advancing the release/head/job/outbox share ONE SQLite commit.
const sqliteStablePermitDDL0374 = `CREATE TABLE IF NOT EXISTS http_stable_permits_0374 (
    token_sha256 TEXT PRIMARY KEY CHECK(length(token_sha256)=64),
    package_id TEXT NOT NULL, project_id TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64),
    artifact_sha256 TEXT NOT NULL CHECK(length(artifact_sha256)=64),
    matrix_sha256 TEXT NOT NULL CHECK(length(matrix_sha256)=64),
    targets_json BLOB NOT NULL, runs_json BLOB NOT NULL, attestor_key TEXT NOT NULL,
    issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    consumed_at INTEGER CHECK(consumed_at IS NULL OR consumed_at>=issued_at)
);
CREATE INDEX IF NOT EXISTS http_stable_permits_package_0374 ON http_stable_permits_0374(package_id,expires_at);`

// The struct order matches the v4 signed attestation payload exactly. It is
// not a loose map: json.Marshal of this typed value reconstructs the canonical
// Ed25519 message that the independent attestor signed.
type sqliteSignedEvidence0374 struct {
	SchemaVersion        string            `json:"schemaVersion"`
	RunNonce             string            `json:"runNonce"`
	Audience             string            `json:"audience"`
	Purpose              string            `json:"purpose"`
	TargetID             string            `json:"targetId"`
	TargetMatrixSHA256   string            `json:"targetMatrixSha256"`
	SignerKeyID          string            `json:"signerKeyId"`
	PackageVersion       string            `json:"packageVersion"`
	RunID                string            `json:"runId"`
	PackageID            string            `json:"packageId"`
	ManifestSHA256       string            `json:"manifestSha256"`
	ArtifactSHA256       string            `json:"artifactSha256"`
	ResolvedPlanSHA256   string            `json:"resolvedPlanSha256"`
	SourceSHA            string            `json:"sourceSha"`
	BuildSHA             string            `json:"buildSha"`
	RunnerImageSHA256    string            `json:"runnerImageSha256"`
	JavaSHA256           string            `json:"javaSha256"`
	JavaVersion          string            `json:"javaVersion"`
	OS                   string            `json:"os"`
	Arch                 string            `json:"arch"`
	Loader               string            `json:"loader"`
	InstallAdapterSHA256 string            `json:"installAdapterSha256"`
	GuardMode            string            `json:"guardMode"`
	GuardPolicySHA256    string            `json:"guardPolicySha256"`
	ServerBridgeSHA256   string            `json:"serverBridgeSha256"`
	ServerPluginVersion  string            `json:"serverPluginVersion"`
	Preset               string            `json:"preset"`
	AuthenticationMode   string            `json:"authenticationMode"`
	Stages               map[string]string `json:"stages"`
	ArtifactHashes       map[string]string `json:"artifactHashes"`
	StartedAt            string            `json:"startedAt"`
	FinishedAt           string            `json:"finishedAt"`
	IssuedAt             string            `json:"issuedAt"`
	ExpiresAt            string            `json:"expiresAt"`
}

func verifySignedSQLiteEvidence0374(raw []byte, signature, key string) bool {
	pub, e := base64.RawURLEncoding.DecodeString(key)
	if e != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	signed, e := base64.RawURLEncoding.DecodeString(signature)
	if e != nil || len(signed) != ed25519.SignatureSize {
		return false
	}
	var payload sqliteSignedEvidence0374
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&payload) != nil {
		return false
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return false
	}
	fp := sha256.Sum256(pub)
	if hex.EncodeToString(fp[:]) != payload.SignerKeyID {
		return false
	}
	canonical, e := json.Marshal(payload)
	if e != nil {
		return false
	}
	message := append([]byte("Launcher/validation-evidence/v4\x00"), canonical...)
	return ed25519.Verify(ed25519.PublicKey(pub), message, signed)
}

func validSQLiteAttestorKey0374(key string) bool {
	pub, err := base64.RawURLEncoding.DecodeString(key)
	return err == nil && len(pub) == ed25519.PublicKeySize
}

var stableStageArtifacts0374 = map[string]string{
	"materialization": "verified.json", "startup": "startup-readiness.json",
	"loader-readiness": "startup-readiness.json", "authentication": "authentication.json",
	"server-readiness": "server-readiness.json", "matching-server": "gameplay-smoke.json",
	"gameplay-smoke": "gameplay-smoke.json", "update-recovery": "update-recovery.json",
}

var requiredStableStages0374 = [...]string{
	"manifest-files", "materialization", "startup", "loader-readiness", "authentication",
	"server-readiness", "matching-server", "gameplay-smoke", "update-recovery",
}
var boundStableFields0374 = [...]string{
	"targetId", "packageVersion", "manifestSha256", "artifactSha256", "resolvedPlanSha256",
	"sourceSha", "buildSha", "javaSha256", "javaVersion", "os", "arch", "loader",
	"installAdapterSha256", "guardMode", "guardPolicySha256", "serverBridgeSha256",
	"serverPluginVersion", "preset", "authenticationMode",
}
var targetStableFields0374 = [...]string{
	"id", "version", "manifestSha256", "artifactSha256", "resolvedPlanSha256",
	"sourceSha", "buildSha", "javaSha256", "javaVersion", "os", "arch", "loader",
	"installAdapterSha256", "guardMode", "guardPolicySha256", "serverBridgeSha256",
	"serverPluginVersion", "preset", "authenticationMode",
}

func stableHex0374(v string) bool {
	if len(v) != 64 || strings.ToLower(v) != v {
		return false
	}
	_, e := hex.DecodeString(v)
	return e == nil
}

func parseStableTargets0374(raw json.RawMessage, runs map[string]string, project, manifest, artifact string) ([]map[string]string, error) {
	var targets []map[string]string
	if json.Unmarshal(raw, &targets) != nil || len(targets) == 0 || len(targets) > 128 || len(runs) != len(targets) {
		return nil, ErrStableRuntimeGate0341
	}
	seen := make(map[string]bool, len(targets))
	for _, target := range targets {
		id := target["id"]
		if id == "" || seen[id] || runs[id] == "" || target["projectId"] != project || target["manifestSha256"] != manifest || target["artifactSha256"] != artifact {
			return nil, ErrStableRuntimeGate0341
		}
		for _, field := range targetStableFields0374 {
			if target[field] == "" {
				return nil, ErrStableRuntimeGate0341
			}
		}
		seen[id] = true
	}
	return targets, nil
}

// IssueStableRuntimePermit03411 is invoked exclusively after the API verifies
// signatures, the configured platform matrix and observed execution. SQLite
// stores a hashed, short-lived grant and rechecks immutable recorded evidence,
// live revocation and the full required matrix at the final write boundary.
func (r *SQLiteHTTPRepository0372) IssueStableRuntimePermit03411(ctx context.Context, p StableRuntimePermit03411) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed != nil {
		return "", r.failed
	}
	if !validSQLiteAttestorKey0374(p.TrustedAttestorKey0374) || !stableHex0374(p.ManifestSHA256) || !stableHex0374(p.ArtifactSHA256) || !stableHex0374(p.MatrixSHA256) || p.PackageID == "" || p.ProjectID == "" {
		return "", ErrStableRuntimeGate0341
	}
	if _, e := parseStableTargets0374(p.TargetsJSON, p.Runs, p.ProjectID, p.ManifestSHA256, p.ArtifactSHA256); e != nil {
		return "", e
	}
	present := false
	for _, rel := range r.mem.releases {
		if rel.ID == p.PackageID && rel.ProjectID == p.ProjectID && IsStableChannel0341(rel.Channel) && rel.Status != "published" {
			present = true
			break
		}
	}
	if !present {
		return "", ErrStableRuntimeGate0341
	}
	var bytes [32]byte
	if _, e := rand.Read(bytes[:]); e != nil {
		return "", e
	}
	token := hex.EncodeToString(bytes[:])
	hash := sha256.Sum256([]byte(token))
	encodedRuns, e := json.Marshal(p.Runs)
	if e != nil {
		return "", e
	}
	now := time.Now().UTC()
	e = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		_, e := q.ExecContext(ctx, `DELETE FROM http_stable_permits_0374 WHERE expires_at<? AND consumed_at IS NULL`, now.Add(-24*time.Hour).UnixNano())
		if e != nil {
			return e
		}
		_, e = q.ExecContext(ctx, `INSERT INTO http_stable_permits_0374(token_sha256,package_id,project_id,manifest_sha256,artifact_sha256,matrix_sha256,targets_json,runs_json,attestor_key,issued_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`, hex.EncodeToString(hash[:]), p.PackageID, p.ProjectID, p.ManifestSHA256, p.ArtifactSHA256, p.MatrixSHA256, []byte(p.TargetsJSON), encodedRuns, p.TrustedAttestorKey0374, now.UnixNano(), now.Add(5*time.Minute).UnixNano())
		return e
	})
	if e != nil {
		return "", fmt.Errorf("persist sqlite stable grant: %w", e)
	}
	return token, nil
}

// The caller holds r.mu; no other SQLite repository mutation, revocation,
// permit creation or job transition may interleave before its WAL commit.
func (r *SQLiteHTTPRepository0372) validateStablePermit0374(q sqlitedurable.Executor, ctx context.Context, token string, rel model.ReleaseVersion, manifest, artifact string) error {
	if !stableHex0374(token) {
		return ErrStableRuntimeGate0341
	}
	hash := sha256.Sum256([]byte(token))
	var project, packageID, md, ad, matrix, attestorKey string
	var targetsRaw, runsRaw []byte
	var issued, expires int64
	e := q.QueryRowContext(ctx, `SELECT package_id,project_id,manifest_sha256,artifact_sha256,matrix_sha256,targets_json,runs_json,attestor_key,issued_at,expires_at FROM http_stable_permits_0374 WHERE token_sha256=? AND consumed_at IS NULL`, hex.EncodeToString(hash[:])).Scan(&packageID, &project, &md, &ad, &matrix, &targetsRaw, &runsRaw, &attestorKey, &issued, &expires)
	if errors.Is(e, sql.ErrNoRows) {
		return ErrStableRuntimeGate0341
	}
	if e != nil {
		return e
	}
	now := time.Now().UTC()
	if !validSQLiteAttestorKey0374(attestorKey) || now.UnixNano() >= expires || expires-issued > int64(5*time.Minute) || issued > now.UnixNano() || packageID != rel.ID || project != rel.ProjectID || md != manifest || ad != artifact || !stableHex0374(matrix) {
		return ErrStableRuntimeGate0341
	}
	var runs map[string]string
	if json.Unmarshal(runsRaw, &runs) != nil {
		return ErrStableRuntimeGate0341
	}
	targets, e := parseStableTargets0374(targetsRaw, runs, project, md, ad)
	if e != nil {
		return e
	}
	for _, target := range targets {
		if target["profileId"] != rel.ProfileID || target["channel"] != "stable" || target["version"] != rel.Version {
			return ErrStableRuntimeGate0341
		}
	}
	var latest model.IntegrityCheckResult
	for _, check := range r.mem.integrityChecks {
		if check.PackageID == packageID && (latest.CheckedAt.IsZero() || check.CheckedAt.After(latest.CheckedAt) || (check.CheckedAt.Equal(latest.CheckedAt) && check.ID > latest.ID)) {
			latest = check
		}
	}
	if latest.Result != "passed" || latest.ManifestDigest != md || latest.ArtifactDigest != ad {
		return ErrStableRuntimeGate0341
	}
	for _, t := range targets {
		runID := runs[t["id"]]
		challenge, exists := r.mem.validationChallenges0346[runID]
		if !exists || challenge.PackageID != packageID || challenge.ProjectID != project || challenge.ManifestSHA256 != md || challenge.ArtifactSHA256 != ad || challenge.TargetMatrixSHA256 != matrix || !challenge.ExpiresAt.After(challenge.IssuedAt) {
			return ErrStableRuntimeGate0341
		}
		found := false
		var verifiedEvidence map[string]json.RawMessage
		for _, a := range r.mem.validationAttestations0345 {
			if a.RunID != runID || a.PackageID != packageID || a.ProjectID != project || a.ManifestSHA256 != md || a.ArtifactSHA256 != ad {
				continue
			}
			var evidence map[string]json.RawMessage
			if !verifySignedSQLiteEvidence0374(a.Evidence, a.Signature, attestorKey) || json.Unmarshal(a.Evidence, &evidence) != nil {
				continue
			}
			field := func(k string) string { var value string; _ = json.Unmarshal(evidence[k], &value); return value }
			if field("runNonce") != challenge.Nonce || field("targetMatrixSha256") != matrix || field("schemaVersion") != "launcher.validation-evidence.v4" || field("audience") != "launcher-api/validation-evidence/0.34.7" || field("purpose") != "staged-package-runtime-verification" || field("runId") != runID || field("packageId") != packageID {
				continue
			}
			expiry, parseErr := time.Parse(time.RFC3339Nano, field("expiresAt"))
			if parseErr != nil || !expiry.After(now) {
				continue
			}
			signingKey := field("signerKeyId")
			if !stableHex0374(signingKey) || r.mem.validationRevocations0346[signingKey] {
				continue
			}
			matched := true
			for i, key := range boundStableFields0374 {
				if subtle.ConstantTimeCompare([]byte(field(key)), []byte(t[targetStableFields0374[i]])) != 1 {
					matched = false
					break
				}
			}
			var stages map[string]string
			if json.Unmarshal(evidence["stages"], &stages) != nil {
				continue
			}
			for _, stage := range requiredStableStages0374 {
				if stages[stage] != "passed" {
					matched = false
					break
				}
			}
			if matched {
				found = true
				verifiedEvidence = evidence
				break
			}
		}
		if !found {
			return ErrStableRuntimeGate0341
		}
		// Preserve the independent execution report binding; this prevents a
		// signed attestation from being assigned to a different stored run.
		reportFound := false
		for _, run := range r.mem.stagedRuntimeRuns0342 {
			if run.RunID != runID || run.PackageID != packageID || run.ProjectID != project || run.ManifestSHA256 != md || run.ArtifactSHA256 != ad {
				continue
			}
			verifiedField := func(k string) string { var v string; _ = json.Unmarshal(verifiedEvidence[k], &v); return v }
			var steps map[string]struct {
				Status         string `json:"status"`
				EvidenceSHA256 string `json:"evidenceSha256"`
			}
			if json.Unmarshal(run.Stages, &steps) != nil {
				continue
			}
			started, errStart := time.Parse(time.RFC3339Nano, verifiedField("startedAt"))
			finished, errFinish := time.Parse(time.RFC3339Nano, verifiedField("finishedAt"))
			if errStart != nil || errFinish != nil || !started.Equal(run.StartedAt) || !finished.Equal(run.FinishedAt) {
				continue
			}
			var hashes map[string]string
			if json.Unmarshal(verifiedEvidence["artifactHashes"], &hashes) != nil {
				continue
			}
			matchedReport := true
			for _, name := range requiredStableStages0374 {
				step, ok := steps[name]
				if !ok || step.Status != "passed" {
					matchedReport = false
					break
				}
				if artifactName := stableStageArtifacts0374[name]; artifactName != "" && (hashes[artifactName] == "" || step.EvidenceSHA256 != hashes[artifactName]) {
					matchedReport = false
					break
				}
			}
			if !matchedReport {
				continue
			}
			reportFound = true
			break
		}
		if !reportFound {
			return ErrStableRuntimeGate0341
		}
	}
	return nil
}

func (r *SQLiteHTTPRepository0372) CommitDurablePublish(ctx context.Context, commit model.DurablePublishCommit) (out model.ReleaseVersion, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		return out, r.failed
	}
	// All errors are non-mutating until the durable job is actually committed.
	job, exists := r.mem.durableJobs[commit.JobID]
	if !exists {
		return out, ErrNotFound
	}
	var rel model.ReleaseVersion
	found := false
	for _, v := range r.mem.releases {
		if v.ID == job.ResourceID && v.ProjectID == job.ProjectID {
			rel = v
			found = true
			break
		}
	}
	if !found {
		return out, ErrNotFound
	}
	// The non-stable path retains existing behavior, but never writes if its
	// domain preconditions failed (no spurious SQLite sequence increment).
	if !IsStableChannel0341(rel.Channel) {
		out, err = r.mem.commitDurablePublish0213(ctx, commit, false)
		if err != nil {
			return out, err
		}
		if err = r.persist(context.Background()); err != nil {
			r.failed = err
			return model.ReleaseVersion{}, err
		}
		return out, nil
	}
	// For stable the permit is verified AGAIN within the same write transaction
	// that consumes it, including fresh revocation and every target stage.
	mutated := false
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		// Check the job snapshot before attempting a grant lookup.
		canonical, e := json.Marshal(rel.Manifest)
		if e != nil {
			return e
		}
		digest := sha256.Sum256(canonical)
		md := hex.EncodeToString(digest[:])
		if md != commit.ExpectedManifestDigest {
			return ErrConflict
		}
		if e = r.validateStablePermit0374(q, ctx, commit.StableGateToken03411, rel, md, commit.ExpectedArtifactDigest); e != nil {
			return e
		}
		out, e = r.mem.commitDurablePublish0213(ctx, commit, true)
		if e != nil {
			return e
		}
		mutated = true
		r.mem.AddAuditEvent(model.AuditEvent{Actor: commit.ActorID, Action: "package:publish", Target: rel.ID, JobID: commit.JobID, CreatedAt: time.Now().UTC()})
		raw, e := json.Marshal(snapshotSQLiteHTTP0372(r.mem))
		if e != nil {
			return e
		}
		sum := sha256.Sum256(raw)
		result, e := q.ExecContext(ctx, `UPDATE http_repository_state_0372 SET sequence=sequence+1,sha256=?,document=? WHERE singleton=1 AND sequence=? AND state_version=1`, hex.EncodeToString(sum[:]), raw, r.seq)
		if e != nil {
			return e
		}
		affected, e := result.RowsAffected()
		if e != nil {
			return e
		}
		if affected != 1 {
			return ErrConflict
		}
		hash := sha256.Sum256([]byte(commit.StableGateToken03411))
		result, e = q.ExecContext(ctx, `UPDATE http_stable_permits_0374 SET consumed_at=? WHERE token_sha256=? AND consumed_at IS NULL AND expires_at>?`, time.Now().UTC().UnixNano(), hex.EncodeToString(hash[:]), time.Now().UTC().UnixNano())
		if e != nil {
			return e
		}
		affected, e = result.RowsAffected()
		if e != nil {
			return e
		}
		if affected != 1 {
			return ErrStableRuntimeGate0341
		}
		return nil
	})
	if err != nil {
		if mutated {
			r.failed = fmt.Errorf("sqlite stable publish outcome must be reconciled after WAL failure: %w", err)
		}
		return model.ReleaseVersion{}, err
	}
	r.seq++
	return out, nil
}
