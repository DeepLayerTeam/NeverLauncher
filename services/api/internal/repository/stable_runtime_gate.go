package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// A one-commit, content-bound permit issued only after the API verifies each
// required signed attestation. The database checks the referenced attestation
// rows again under locks before changing a protected channel head.
type StableRuntimePermit03411 struct {
	PackageID      string
	ProjectID      string
	ManifestSHA256 string
	ArtifactSHA256 string
	MatrixSHA256   string
	TargetsJSON    json.RawMessage
	Runs           map[string]string
	// TrustedAttestorKey0374 is the API-configured Ed25519 public key, a runner-supplied key.
	TrustedAttestorKey0374 string
}

func (r *SQLRepository) IssueStableRuntimePermit03411(ctx context.Context, p StableRuntimePermit03411) (string, error) {
	if e := r.check(); e != nil {
		return "", e
	}
	var targets []json.RawMessage
	if json.Unmarshal(p.TargetsJSON, &targets) != nil || len(targets) == 0 || len(targets) > 128 || len(p.Runs) != len(targets) {
		return "", errors.New("invalid required stable target coverage")
	}
	for _, t := range targets {
		var v struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(t, &v) != nil || v.ID == "" || p.Runs[v.ID] == "" {
			return "", errors.New("missing run for stable target")
		}
	}
	if len(p.ManifestSHA256) != 64 || len(p.ArtifactSHA256) != 64 || len(p.MatrixSHA256) != 64 {
		return "", errors.New("invalid stable snapshot digest")
	}
	runs, e := json.Marshal(p.Runs)
	if e != nil {
		return "", e
	}
	var buf [32]byte
	if _, e = rand.Read(buf[:]); e != nil {
		return "", e
	}
	token := hex.EncodeToString(buf[:])
	digest := sha256.Sum256([]byte(token))
	now := time.Now().UTC()
	// Expired permits have no operational value; persisted attestations and
	// audit events retain the permanent history.
	if _, e = r.db.ExecContext(ctx, `DELETE FROM stable_runtime_permits_03411 WHERE expires_at < now()-interval '1 day'`); e != nil {
		return "", e
	}
	_, e = r.db.ExecContext(ctx, `INSERT INTO stable_runtime_permits_03411(token_sha256,package_id,project_id,manifest_sha256,artifact_sha256,matrix_sha256,targets,runs,issued_at,expires_at)
 VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9,$10)`, hex.EncodeToString(digest[:]), p.PackageID, p.ProjectID, p.ManifestSHA256, p.ArtifactSHA256, p.MatrixSHA256, string(p.TargetsJSON), string(runs), now, now.Add(5*time.Minute))
	if e != nil {
		return "", e
	}
	return token, nil
}

// PostgreSQL and SQLite use one-use, snapshot-bound stable grants. Direct
// non-durable publish paths remain denied; durable jobs store the token.
type stablePermitContextKey03411 struct{}

func WithStablePermit03411(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, stablePermitContextKey03411{}, token)
}
func stablePermitToken03411(ctx context.Context) string {
	token, _ := ctx.Value(stablePermitContextKey03411{}).(string)
	return token
}
