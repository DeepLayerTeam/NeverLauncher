package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// A staging grant conveys read/report access ONLY to one already integrity-checked
// release snapshot. It is not runtime attestation and cannot certify stable.
const stagedGrantSchema0342 = "neverlauncher.staged-runtime-grant.v1"
const stagedRunSchema0342 = "neverlauncher.staged-runtime-run.v1"

type stagedGrant0342 struct {
	Schema         string `json:"schema"`
	PackageID      string `json:"packageId"`
	ProjectID      string `json:"projectId"`
	ManifestSHA256 string `json:"manifestSha256"`
	ArtifactSHA256 string `json:"artifactSha256"`
	RunID          string `json:"runId"`
	Nonce          string `json:"nonce,omitempty"`
	ExpiresAt      int64  `json:"expiresAt"`
}

type stagedStep0342 struct {
	Status         string `json:"status"`
	Detail         string `json:"detail,omitempty"`
	EvidenceSHA256 string `json:"evidenceSha256,omitempty"`
}

type stagedRunReport0342 struct {
	Schema         string                    `json:"schemaVersion"`
	RunID          string                    `json:"runId"`
	PackageID      string                    `json:"packageId"`
	ManifestSHA256 string                    `json:"manifestSha256"`
	ArtifactSHA256 string                    `json:"artifactSha256"`
	StartedAt      time.Time                 `json:"startedAt"`
	FinishedAt     time.Time                 `json:"finishedAt"`
	Stages         map[string]stagedStep0342 `json:"stages"`
}

type stagedRunWriter0342 interface {
	SaveStagedRun0342(context.Context, model.StagedRuntimeRun0342) error
	ListStagedRuns0342(context.Context, string) ([]model.StagedRuntimeRun0342, error)
}

func (s Server) grantMAC0342(data []byte) ([]byte, error) {
	if len(s.Config.AuthTokenSecret) < 24 {
		return nil, errors.New("staged runner requires configured backend auth secret")
	}
	m := hmac.New(sha256.New, []byte("NeverLauncher/staged-runtime/0.34.2\x00"+s.Config.AuthTokenSecret))
	_, _ = m.Write(data)
	return m.Sum(nil), nil
}
func (s Server) issueGrant0342(claim stagedGrant0342) (string, error) {
	raw, err := json.Marshal(claim)
	if err != nil {
		return "", err
	}
	mac, err := s.grantMAC0342(raw)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(mac), nil
}
func (s Server) parseGrant0342(token string) (stagedGrant0342, error) {
	var g stagedGrant0342
	parts := strings.Split(token, ".")
	if len(parts) != 2 || len(token) > 4096 {
		return g, errors.New("invalid staging grant")
	}
	raw, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil || len(raw) > 2048 {
		return g, errors.New("invalid staging grant payload")
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		return g, errors.New("invalid staging grant signature")
	}
	expected, e := s.grantMAC0342(raw)
	if e != nil || !hmac.Equal(sig, expected) {
		return g, errors.New("invalid staging grant signature")
	}
	if e = json.Unmarshal(raw, &g); e != nil {
		return g, e
	}
	if g.Schema != stagedGrantSchema0342 || g.RunID == "" || (g.Nonce != "" && (len(g.Nonce) != 64 || !hexSHA0342(g.Nonce))) || g.PackageID == "" || g.ProjectID == "" || len(g.ManifestSHA256) != 64 || len(g.ArtifactSHA256) != 64 || g.ExpiresAt <= time.Now().UTC().Unix() || g.ExpiresAt > time.Now().UTC().Add(2*time.Hour).Unix()+60 {
		return g, errors.New("staging grant expired or invalid")
	}
	return g, nil
}
func (s Server) stagedSnapshot0342(ctx context.Context, g stagedGrant0342) (packageLookup, error) {
	lookup, err := s.lookupPackage(g.PackageID)
	if err != nil {
		return lookup, err
	}
	if lookup.Release.ID != g.PackageID || lookup.Release.ProjectID != g.ProjectID || lookup.Release.Status != "integrity-passed" {
		return lookup, errors.New("staged release is no longer eligible")
	}
	md, err := manifestDigest0212(lookup.Release.Manifest)
	if err != nil {
		return lookup, err
	}
	fd, err := artifactDigest0212(lookup.Files)
	if err != nil {
		return lookup, err
	}
	if md != g.ManifestSHA256 || fd != g.ArtifactSHA256 {
		return lookup, errors.New("staged release changed after grant issuance")
	}
	if err = s.verifyManifestSignature(lookup.Release.Manifest); err != nil {
		return lookup, err
	}
	if !manifestFilesMatch0212(lookup.Release.Manifest, lookup.Files) {
		return lookup, errors.New("staged manifest does not match files")
	}
	check, err := s.Repo.LatestIntegrityCheck(ctx, g.PackageID)
	if err != nil || check.Result != "passed" || check.ManifestDigest != md || check.ArtifactDigest != fd {
		return lookup, errors.New("staged integrity proof missing or stale")
	}
	return lookup, nil
}
func (s Server) authorizeStaged0342(w http.ResponseWriter, r *http.Request) (stagedGrant0342, packageLookup, bool) {
	var empty stagedGrant0342
	var no packageLookup
	bearer := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(bearer, "Bearer ") {
		writeError(w, http.StatusUnauthorized, "staged runner grant required")
		return empty, no, false
	}
	g, err := s.parseGrant0342(strings.TrimSpace(strings.TrimPrefix(bearer, "Bearer ")))
	if err != nil || g.PackageID != r.PathValue("packageId") {
		writeError(w, http.StatusUnauthorized, "invalid or expired staged runner grant")
		return empty, no, false
	}
	lookup, err := s.stagedSnapshot0342(r.Context(), g)
	if err != nil {
		writeError(w, http.StatusConflict, "staged snapshot is no longer valid: "+err.Error())
		return empty, no, false
	}
	return g, lookup, true
}
func (s Server) stagedRunIssue0342(w http.ResponseWriter, r *http.Request) {
	lookup, err := s.lookupPackage(r.PathValue("packageId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "package not found")
		return
	}
	if lookup.Release.Status != "integrity-passed" {
		writeError(w, http.StatusConflict, "package must have passed staged integrity check")
		return
	}
	if len(lookup.Files) == 0 {
		writeError(w, http.StatusConflict, "staged package has no downloadable runtime content")
		return
	}
	md, e := manifestDigest0212(lookup.Release.Manifest)
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	fd, e := artifactDigest0212(lookup.Files)
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	// No grant is issued if signed metadata or an actual storage object fails verification.
	if _, e = s.stagedSnapshot0342(r.Context(), stagedGrant0342{PackageID: lookup.Release.ID, ProjectID: lookup.Release.ProjectID, ManifestSHA256: md, ArtifactSHA256: fd}); e != nil {
		writeError(w, 409, e.Error())
		return
	}
	if !checksPassed0212(s.validatePackageFiles(lookup.Release, lookup.Files)) {
		writeError(w, 409, "staged storage has missing or corrupted files")
		return
	}
	var nonce [24]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		writeError(w, 500, "secure run ID unavailable")
		return
	}
	// Persist a separate one-time challenge BEFORE a worker can report a run.
	// A plain staged run can remain diagnostic without target configuration, but
	// it cannot produce a trusted attestation while the policy is unconfigured.
	targetHash := strings.Repeat("0", 64)
	var targets []validationTarget0346
	if strings.TrimSpace(s.Config.ValidationRequiredTargetsJSON0346) != "" {
		var pe error
		targets, targetHash, pe = configuredTargets0346(s.Config.ValidationRequiredTargetsJSON0346, lookup.Release, md, fd)
		if pe != nil {
			writeError(w, 409, "runtime target policy rejected: "+pe.Error())
			return
		}
	}
	var challengeNonce [32]byte
	if _, e = rand.Read(challengeNonce[:]); e != nil {
		writeError(w, 503, "challenge nonce unavailable")
		return
	}
	issuedAt := time.Now().UTC().Truncate(time.Microsecond)
	grant := stagedGrant0342{Schema: stagedGrantSchema0342, PackageID: lookup.Release.ID, ProjectID: lookup.Release.ProjectID, ManifestSHA256: md, ArtifactSHA256: fd, RunID: hex.EncodeToString(nonce[:]), Nonce: hex.EncodeToString(challengeNonce[:]), ExpiresAt: time.Now().UTC().Add(90 * time.Minute).Unix()}
	freshStore, available := s.Repo.(validationFreshnessStore0346)
	if !available {
		writeError(w, 503, "validation challenge persistence unavailable")
		return
	}
	challenge := model.ValidationChallenge0346{RunID: grant.RunID, Nonce: grant.Nonce, PackageID: grant.PackageID, ProjectID: grant.ProjectID, ManifestSHA256: md, ArtifactSHA256: fd, TargetMatrixSHA256: targetHash, IssuedAt: issuedAt, ExpiresAt: time.Unix(grant.ExpiresAt, 0).UTC()}
	if e = freshStore.SaveValidationChallenge0346(r.Context(), challenge); e != nil {
		writeError(w, 503, "cannot persist validation challenge")
		return
	}
	token, e := s.issueGrant0342(grant)
	if e != nil {
		writeError(w, 503, e.Error())
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{Actor: s.adminActor(r), Action: "staged-runtime:grant-issued", Target: grant.PackageID, JobID: grant.RunID, CreatedAt: time.Now().UTC()})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, map[string]any{"data": map[string]any{"schemaVersion": stagedGrantSchema0342, "token": token, "runId": grant.RunID, "nonce": grant.Nonce, "issuedAt": issuedAt, "targetMatrixSha256": targetHash, "requiredTargets": targets, "expiresAt": time.Unix(grant.ExpiresAt, 0).UTC(), "packageId": grant.PackageID, "manifestSha256": md, "artifactSha256": fd, "snapshotPath": "/api/v1/staged-runs/" + grant.PackageID + "/snapshot", "attested": false}})
}
func (s Server) stagedRunDownloadManifest0342(w http.ResponseWriter, r *http.Request) {
	g, lookup, ok := s.authorizeStaged0342(w, r)
	if !ok {
		return
	}
	// This is the signed release manifest plus a client-consumable description.
	// The worker downloads bytes separately and installs them using the regular updater.
	files := make([]map[string]any, 0, len(lookup.Files))
	for _, f := range lookup.Files {
		files = append(files, map[string]any{"path": f.Path, "size": f.Size, "sha256": strings.ToLower(f.SHA256), "url": "/api/v1/staged-runs/" + g.PackageID + "/files/" + stagedEscapePath0342(f.Path), "required": f.Required, "group": f.Ownership, "executable": f.Executable, "targetOs": f.TargetOS})
	}
	p := map[string]any{"schemaVersion": "neverlauncher.client-package.v1", "packageId": g.PackageID, "projectId": g.ProjectID, "profileId": lookup.Release.ProfileID, "channel": lookup.Release.Channel, "version": lookup.Release.Version, "files": files}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"schemaVersion": stagedRunSchema0342, "runId": g.RunID, "packageId": g.PackageID, "manifestSha256": g.ManifestSHA256, "artifactSha256": g.ArtifactSHA256, "signedManifest": lookup.Release.Manifest, "package": p})
}
func stagedEscapePath0342(p string) string {
	segments := strings.Split(p, "/")
	for i := range segments {
		segments[i] = url.PathEscape(segments[i])
	}
	return strings.Join(segments, "/")
}

func (s Server) stagedRunDownloadFile0342(w http.ResponseWriter, r *http.Request) {
	_, lookup, ok := s.authorizeStaged0342(w, r)
	if !ok {
		return
	}
	requested := r.PathValue("path")
	if requested == "" || path.Clean(requested) != requested || strings.HasPrefix(requested, "/") || strings.HasPrefix(requested, "../") || strings.Contains(requested, "\\") {
		writeError(w, 400, "unsafe staged path")
		return
	}
	var file *model.FileObject
	for i := range lookup.Files {
		if lookup.Files[i].Path == requested {
			file = &lookup.Files[i]
			break
		}
	}
	if file == nil {
		writeError(w, 404, "file not in frozen staged manifest")
		return
	}
	reader, size, err := s.Storage.Open(lookup.Release.ProjectID, lookup.Release.ID, requested)
	if err != nil {
		writeError(w, 409, "staged object unavailable")
		return
	}
	defer reader.Close()
	if file.Size < 0 || file.Size > s.maxUploadBytes() {
		writeError(w, http.StatusRequestEntityTooLarge, "staged object exceeds delivery size limit")
		return
	}
	if size != file.Size {
		writeError(w, 409, "staged object size mismatch")
		return
	}
	// Read to a bounded temporary file, hash before sending any HTTP 200 bytes.
	tmp, err := os.CreateTemp("", "neverlauncher-staged-0342-*")
	if err != nil {
		writeError(w, 503, "staged temporary storage unavailable")
		return
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(reader, file.Size+1))
	if err != nil || n != file.Size {
		writeError(w, 409, "staged object read mismatch")
		return
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if sum != strings.ToLower(file.SHA256) {
		writeError(w, 409, "staged object digest mismatch")
		return
	}
	if _, err = tmp.Seek(0, 0); err != nil {
		writeError(w, 503, "staged temporary file unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprint(n))
	w.Header().Set("X-Content-SHA256", sum)
	_, _ = io.Copy(w, tmp)
}
func validateStagedRunReport0342(g stagedGrant0342, p stagedRunReport0342) error {
	if p.Schema != stagedRunSchema0342 || p.PackageID != g.PackageID || p.RunID != g.RunID || p.ManifestSHA256 != g.ManifestSHA256 || p.ArtifactSHA256 != g.ArtifactSHA256 {
		return errors.New("run identity or snapshot mismatch")
	}
	if p.StartedAt.IsZero() || p.FinishedAt.Before(p.StartedAt) || p.FinishedAt.After(time.Now().Add(5*time.Minute)) || p.StartedAt.Before(time.Unix(g.ExpiresAt, 0).Add(-95*time.Minute)) {
		return errors.New("invalid execution times")
	}
	if len(p.Stages) == 0 || len(p.Stages) > 10 {
		return errors.New("missing or excessive stages")
	}
	for k, v := range p.Stages {
		if k != "manifest-files" && k != "materialization" && k != "startup" && k != "loader-readiness" && k != "authentication" && k != "server-readiness" && k != "matching-server" && k != "gameplay-smoke" && k != "update-recovery" {
			return errors.New("invalid execution stage")
		}
		if v.Status != "passed" && v.Status != "failed" && v.Status != "blocked" && v.Status != "inconclusive" {
			return errors.New("invalid execution status")
		}
		if len(v.Detail) > 2048 || (v.EvidenceSHA256 != "" && (len(v.EvidenceSHA256) != 64 || !hexSHA0342(v.EvidenceSHA256))) {
			return errors.New("invalid stage detail or digest")
		}
	}
	return nil
}
func hexSHA0342(s string) bool { _, e := hex.DecodeString(s); return e == nil }
func (s Server) stagedRunReport0342(w http.ResponseWriter, r *http.Request) {
	g, _, ok := s.authorizeStaged0342(w, r)
	if !ok {
		return
	}
	writer, ok := s.Repo.(stagedRunWriter0342)
	if !ok {
		writeError(w, 503, "runtime report repository unavailable")
		return
	}
	var p stagedRunReport0342
	r.Body = http.MaxBytesReader(w, r.Body, 24<<10)
	incoming, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		writeError(w, 400, "invalid or oversized execution report")
		return
	}
	dec := json.NewDecoder(bytes.NewReader(incoming))
	dec.DisallowUnknownFields()
	decodeErr := dec.Decode(&p)
	if decodeErr == nil {
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			decodeErr = errors.New("trailing execution report")
		}
	}
	if decodeErr != nil {
		if e := s.saveValidationDecision03412(r.Context(), g.PackageID, g.RunID, "staged-report", "rejected",
			"malformed-observation", digestValidationAttempt03412(incoming)); e != nil {
			writeError(w, 503, "validation audit unavailable")
			return
		}
		writeError(w, 400, "invalid execution report")
		return
	}
	if err := validateStagedRunReport0342(g, p); err != nil {
		// Even an invalid runner report is an attempt, never certification.
		if s.saveValidationDecision03412(r.Context(), g.PackageID, g.RunID, "staged-report", "rejected",
			"invalid-observation", safeValidationDecisionDigest03412(p)) != nil {
			writeError(w, 503, "validation audit unavailable")
			return
		}
		writeError(w, 409, err.Error())
		return
	}
	// Observational diagnostics are untrusted. Never persist credentials,
	// authentication headers, JVM sensitive arguments or account identifiers.
	for name, stage := range p.Stages {
		stage.Detail = redactValidationDetail03412(stage.Detail)
		p.Stages[name] = stage
	}
	raw, _ := json.Marshal(p.Stages)
	report := model.StagedRuntimeRun0342{RunID: g.RunID, PackageID: g.PackageID, ProjectID: g.ProjectID, ManifestSHA256: g.ManifestSHA256, ArtifactSHA256: g.ArtifactSHA256, Stages: raw, StartedAt: p.StartedAt, FinishedAt: p.FinishedAt, ReceivedAt: time.Now().UTC()}
	if err := writer.SaveStagedRun0342(r.Context(), report); err != nil {
		writeError(w, 409, "execution report rejected: "+err.Error())
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{Actor: "staged-runtime-runner", Action: "staged-runtime:report-received", Target: g.PackageID, JobID: g.RunID, ReasonCode: "untrusted-execution-observation", CreatedAt: time.Now().UTC()})
	writeJSON(w, 201, map[string]any{"data": map[string]any{"runId": g.RunID, "recorded": true, "trustedCertification": false, "stablePublishEligible": false}})
}
func (s Server) stagedRunList0342(w http.ResponseWriter, r *http.Request) {
	writer, ok := s.Repo.(stagedRunWriter0342)
	if !ok {
		writeError(w, 503, "runtime report repository unavailable")
		return
	}
	rows, err := writer.ListStagedRuns0342(r.Context(), r.PathValue("packageId"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	for i := range rows {
		var stages map[string]stagedStep0342
		if json.Unmarshal(rows[i].Stages, &stages) == nil {
			for name, step := range stages {
				step.Detail = redactValidationDetail03412(step.Detail)
				stages[name] = step
			}
			rows[i].Stages, _ = json.Marshal(stages)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": map[string]any{"packageId": r.PathValue("packageId"), "runs": rows, "trustedCertification": false}})
}
