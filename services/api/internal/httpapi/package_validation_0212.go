package httpapi

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

const runtimeValidationSchema0212 = "neverlauncher/runtime-validation/v1"

type runtimeValidationEvidence0212 struct {
	SchemaVersion    string            `json:"schemaVersion"`
	PackageID        string            `json:"packageId"`
	ManifestDigest   string            `json:"manifestDigest"`
	TargetID         string            `json:"targetId"`
	MinecraftVersion string            `json:"minecraftVersion"`
	Loader           string            `json:"loader"`
	OS               string            `json:"os"`
	Arch             string            `json:"arch"`
	Java             string            `json:"java"`
	ActualClient     bool              `json:"actualClient"`
	ExitCode         int               `json:"exitCode"`
	ServerJoin       bool              `json:"serverJoin"`
	RunID            string            `json:"runId"`
	Commit           string            `json:"commit"`
	EvidenceHashes   map[string]string `json:"evidenceHashes"`
	StartedAt        time.Time         `json:"startedAt"`
	FinishedAt       time.Time         `json:"finishedAt"`
}

type runtimeValidationSubmission0212 struct {
	KeyID     string                        `json:"keyId"`
	Evidence  runtimeValidationEvidence0212 `json:"evidence"`
	Signature string                        `json:"signature"`
}

type validationPolicyRequest0212 struct {
	RequiredLevel     string `json:"requiredLevel"`
	RequireServerJoin bool   `json:"requireServerJoin"`
}

func manifestDigest0212(manifest model.Manifest) (string, error) {
	raw, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func artifactDigest0212(files []model.FileObject) (string, error) {
	type entry struct {
		Path       string   `json:"path"`
		Size       int64    `json:"size"`
		SHA256     string   `json:"sha256"`
		Executable bool     `json:"executable"`
		TargetOS   []string `json:"targetOs,omitempty"`
	}
	items := make([]entry, 0, len(files))
	for _, f := range files {
		osv := append([]string(nil), f.TargetOS...)
		sort.Strings(osv)
		items = append(items, entry{Path: f.Path, Size: f.Size, SHA256: strings.ToLower(f.SHA256), Executable: f.Executable, TargetOS: osv})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })
	raw, err := json.Marshal(items)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func checksPassed0212(checks []map[string]any) bool {
	if len(checks) == 0 {
		return false
	}
	for _, c := range checks {
		if c["status"] != "ok" {
			return false
		}
	}
	return true
}

func (s Server) runPackageIntegrityCheck0212(r *http.Request, lookup packageLookup) (model.IntegrityCheckResult, error) {
	manifestDigest, err := manifestDigest0212(lookup.Release.Manifest)
	if err != nil {
		return model.IntegrityCheckResult{}, err
	}
	artifactDigest, err := artifactDigest0212(lookup.Files)
	if err != nil {
		return model.IntegrityCheckResult{}, err
	}
	checks := s.validatePackageFiles(lookup.Release, lookup.Files)
	filesOK := checksPassed0212(checks)
	sigOK := s.verifyManifestSignature(lookup.Release.Manifest) == nil
	compatOK := validateCompatibilityManifest(lookup.Release.Manifest) == nil
	passed := filesOK && sigOK && compatOK
	result := model.IntegrityCheckResult{ID: fmt.Sprintf("int-%d", time.Now().UTC().UnixNano()), PackageID: lookup.Release.ID, ProjectID: lookup.Release.ProjectID, ManifestDigest: manifestDigest, ArtifactDigest: artifactDigest, SignatureVerified: sigOK, StorageVerified: filesOK, FilesVerified: filesOK, CompatibilityVerified: compatOK, Result: "failed", Checks: checks, CheckedAt: time.Now().UTC()}
	if passed {
		result.Result = "passed"
	}
	stored, err := s.Repo.SaveIntegrityCheck(r.Context(), result)
	if err != nil {
		return model.IntegrityCheckResult{}, err
	}
	status := "integrity-failed"
	if passed {
		status = "integrity-passed"
	}
	_, _ = s.Repo.UpdateVersionStatus(lookup.Release.ProjectID, lookup.Release.ID, status)
	return stored, nil
}

func (s Server) packageIntegrityCheck0212(w http.ResponseWriter, r *http.Request) {
	unlock := s.lockPackageMutation()
	defer unlock()
	lookup, err := s.lookupPackage(r.PathValue("packageId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "package не найден")
		return
	}
	if lookup.Release.Status == "published" {
		writeError(w, http.StatusConflict, "published release immutable; integrity history доступна через validations")
		return
	}
	if lookup.Release.Status != "staged" && lookup.Release.Status != "integrity-failed" && lookup.Release.Status != "integrity-passed" {
		writeError(w, http.StatusConflict, "package должен быть staged перед integrity-check")
		return
	}
	result, err := s.runPackageIntegrityCheck0212(r, lookup)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "package:integrity-check", lookup.Release.ID)
	s.packageEvent0206(r, "package.integrity-checked", result.Result, lookup.Release)
	if strings.HasSuffix(r.URL.Path, "/smoke-test") {
		s.packageEvent0206(r, "package.smoke-tested", "legacy-integrity:"+result.Result, lookup.Release)
	}
	code := http.StatusOK
	if result.Result != "passed" {
		code = http.StatusConflict
	}
	writeJSON(w, code, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "packageId": lookup.Release.ID, "version": lookup.Release.Version, "status": "integrity-" + result.Result, "validationKind": "integrity", "runtimeExecuted": false, "runtimeStatus": "not-checked", "checks": result.Checks, "result": result}})
}

func (s Server) packageSmoke(w http.ResponseWriter, r *http.Request) {
	// Compatibility route: the historical operation never launched Minecraft.
	// It now calls the canonical integrity implementation and states this explicitly.
	s.packageIntegrityCheck0212(w, r)
}

func decodeRuntimeValidationKey0212(value string) (ed25519.PublicKey, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("empty runtime validation key")
	}
	if raw, err := hex.DecodeString(value); err == nil && len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if raw, err := enc.DecodeString(value); err == nil && len(raw) == ed25519.PublicKeySize {
			return ed25519.PublicKey(raw), nil
		}
	}
	return nil, errors.New("runtime validation public key must be raw Ed25519 hex/base64")
}

func (s Server) runtimeValidationKeys0212() (map[string]ed25519.PublicKey, error) {
	raw := strings.TrimSpace(s.Config.RuntimeValidationKeysJSON)
	if raw == "" {
		return nil, errors.New("runtime validation trust set is not configured")
	}
	var cfg map[string]string
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, errors.New("NEVERLAUNCHER_RUNTIME_VALIDATION_KEYS_JSON must be a JSON object")
	}
	out := make(map[string]ed25519.PublicKey, len(cfg))
	for id, val := range cfg {
		id = strings.TrimSpace(id)
		if id == "" {
			return nil, errors.New("runtime validation key id is empty")
		}
		key, err := decodeRuntimeValidationKey0212(val)
		if err != nil {
			return nil, fmt.Errorf("runtime validation key %q: %w", id, err)
		}
		out[id] = key
	}
	if len(out) == 0 {
		return nil, errors.New("runtime validation trust set is empty")
	}
	return out, nil
}

func canonicalRuntimeEvidence0212(e runtimeValidationEvidence0212) ([]byte, error) {
	return json.Marshal(e)
}

func validSHA256Hex0212(v string) bool {
	if len(v) != 64 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}

func (s Server) packageRuntimeEvidence0212(w http.ResponseWriter, r *http.Request) {
	lookup, err := s.lookupPackage(r.PathValue("packageId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "package не найден")
		return
	}
	var req runtimeValidationSubmission0212
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректное runtime evidence: "+err.Error())
		return
	}
	e := req.Evidence
	e.PackageID = strings.TrimSpace(e.PackageID)
	e.ManifestDigest = strings.ToLower(strings.TrimSpace(e.ManifestDigest))
	e.TargetID = strings.TrimSpace(e.TargetID)
	e.RunID = strings.TrimSpace(e.RunID)
	e.Commit = strings.TrimSpace(e.Commit)
	if e.SchemaVersion != runtimeValidationSchema0212 || e.PackageID != lookup.Release.ID || e.TargetID == "" || e.RunID == "" || !validSHA256Hex0212(e.ManifestDigest) || e.StartedAt.IsZero() || e.FinishedAt.IsZero() || e.FinishedAt.Before(e.StartedAt) {
		writeError(w, http.StatusBadRequest, "runtime evidence identity/schema/timestamps invalid")
		return
	}
	manifestDigest, err := manifestDigest0212(lookup.Release.Manifest)
	if err != nil || e.ManifestDigest != manifestDigest {
		writeError(w, http.StatusConflict, "runtime evidence не привязано к текущему package manifest")
		return
	}
	integrity, err := s.Repo.LatestIntegrityCheck(r.Context(), lookup.Release.ID)
	if err != nil || integrity.Result != "passed" || integrity.ManifestDigest != manifestDigest {
		writeError(w, http.StatusConflict, "runtime evidence принимается только после integrity PASS текущего manifest")
		return
	}
	if len(e.EvidenceHashes) == 0 {
		writeError(w, http.StatusBadRequest, "runtime evidenceHashes не может быть пустым")
		return
	}
	for name, digest := range e.EvidenceHashes {
		if strings.TrimSpace(name) == "" || !validSHA256Hex0212(strings.ToLower(strings.TrimSpace(digest))) {
			writeError(w, http.StatusBadRequest, "runtime evidenceHashes содержит невалидный SHA-256")
			return
		}
	}
	keys, err := s.runtimeValidationKeys0212()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	keyID := strings.TrimSpace(req.KeyID)
	pub, ok := keys[keyID]
	if !ok {
		writeError(w, http.StatusUnauthorized, "runtime validation signer key не доверен")
		return
	}
	canonical, err := canonicalRuntimeEvidence0212(e)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(req.Signature))
	if err != nil {
		if x, e2 := base64.StdEncoding.DecodeString(strings.TrimSpace(req.Signature)); e2 == nil {
			sig = x
		} else {
			writeError(w, http.StatusBadRequest, "runtime evidence signature должна быть base64/base64url")
			return
		}
	}
	if !ed25519.Verify(pub, canonical, sig) {
		writeError(w, http.StatusUnauthorized, "runtime evidence signature недействительна")
		return
	}
	digest := sha256.Sum256(canonical)
	keyFingerprint := sha256.Sum256(pub)
	resultState := "failed"
	if e.ActualClient && e.ExitCode == 0 {
		resultState = "passed"
	}
	result := model.RuntimeValidationResult{ID: fmt.Sprintf("runval-%d", time.Now().UTC().UnixNano()), PackageID: e.PackageID, ProjectID: lookup.Release.ProjectID, ManifestDigest: e.ManifestDigest, TargetID: e.TargetID, MinecraftVersion: e.MinecraftVersion, Loader: e.Loader, OS: e.OS, Arch: e.Arch, Java: e.Java, ActualClient: e.ActualClient, ExitCode: e.ExitCode, ServerJoin: e.ServerJoin, RunID: e.RunID, Commit: e.Commit, EvidenceHashes: e.EvidenceHashes, SignerKeyID: keyID, SignerKeyFingerprint: hex.EncodeToString(keyFingerprint[:]), EvidenceDigest: hex.EncodeToString(digest[:]), StartedAt: e.StartedAt.UTC(), FinishedAt: e.FinishedAt.UTC(), Result: resultState, CreatedAt: time.Now().UTC()}
	stored, err := s.Repo.SaveRuntimeValidation(r.Context(), result)
	if err != nil {
		if errors.Is(err, repository.ErrConflict) {
			writeError(w, http.StatusConflict, "runtime evidence run/target уже использовано")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "package:runtime-validation", lookup.Release.ID+":"+stored.TargetID)
	s.packageEvent0206(r, "package.runtime-validated", stored.TargetID+":"+stored.Result, lookup.Release)
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": apiContractVersion, "data": stored})
}

func (s Server) packageValidations0212(w http.ResponseWriter, r *http.Request) {
	lookup, err := s.lookupPackage(r.PathValue("packageId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "package не найден")
		return
	}
	integrity, integrityErr := s.Repo.LatestIntegrityCheck(r.Context(), lookup.Release.ID)
	runtime, err := s.Repo.ListRuntimeValidations(r.Context(), lookup.Release.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	policy, _ := s.Repo.GetProjectValidationPolicy(r.Context(), lookup.Release.ProjectID)
	var current any = nil
	if integrityErr == nil {
		current = integrity
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"integrity": current, "runtime": runtime, "policy": policy}})
}

func (s Server) projectValidationPolicyGet0212(w http.ResponseWriter, r *http.Request) {
	p, err := s.Repo.GetProjectValidationPolicy(r.Context(), r.PathValue("projectId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "validation policy не найдена")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": p})
}
func (s Server) projectValidationPolicyPut0212(w http.ResponseWriter, r *http.Request) {
	var req validationPolicyRequest0212
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if strings.EqualFold(strings.TrimSpace(req.RequiredLevel), "runtime") {
		if _, err := s.runtimeValidationKeys0212(); err != nil {
			writeError(w, http.StatusConflict, "runtime policy нельзя включить без корректного NEVERLAUNCHER_RUNTIME_VALIDATION_KEYS_JSON: "+err.Error())
			return
		}
	}
	p, err := s.Repo.SaveProjectValidationPolicy(r.Context(), model.ProjectValidationPolicy{ProjectID: r.PathValue("projectId"), RequiredLevel: req.RequiredLevel, RequireServerJoin: req.RequireServerJoin, UpdatedAt: time.Now().UTC()})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "project:validation-policy", p.ProjectID)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": p})
}

func (s Server) validatePublishEvidence0212(r *http.Request, lookup packageLookup) error {
	manifestDigest, err := manifestDigest0212(lookup.Release.Manifest)
	if err != nil {
		return err
	}
	artifactDigest, err := artifactDigest0212(lookup.Files)
	if err != nil {
		return err
	}
	integrity, err := s.Repo.LatestIntegrityCheck(r.Context(), lookup.Release.ID)
	if err != nil {
		return errors.New("publish требует integrity-check текущего package")
	}
	if integrity.Result != "passed" || integrity.ManifestDigest != manifestDigest || integrity.ArtifactDigest != artifactDigest {
		return errors.New("publish требует актуальный integrity PASS для текущих manifest/files")
	}
	policy, err := s.Repo.GetProjectValidationPolicy(r.Context(), lookup.Release.ProjectID)
	if err != nil {
		policy = model.ProjectValidationPolicy{ProjectID: lookup.Release.ProjectID, RequiredLevel: "integrity"}
	}
	if policy.RequiredLevel != "runtime" {
		return nil
	}
	keys, err := s.runtimeValidationKeys0212()
	if err != nil {
		return fmt.Errorf("publish runtime trust set unavailable: %w", err)
	}
	items, err := s.Repo.ListRuntimeValidations(r.Context(), lookup.Release.ID)
	if err != nil {
		return err
	}
	for _, v := range items {
		pub, trusted := keys[v.SignerKeyID]
		if !trusted {
			continue
		}
		fingerprint := sha256.Sum256(pub)
		if v.SignerKeyFingerprint != hex.EncodeToString(fingerprint[:]) {
			continue
		}
		if v.Result == "passed" && v.ManifestDigest == manifestDigest && v.ActualClient && v.ExitCode == 0 && (!policy.RequireServerJoin || v.ServerJoin) {
			return nil
		}
	}
	if policy.RequireServerJoin {
		return errors.New("publish policy требует подписанный runtime PASS текущего manifest с actual client и server join")
	}
	return errors.New("publish policy требует подписанный runtime PASS текущего manifest с actual client")
}

func manifestFilesMatch0212(manifest model.Manifest, files []model.FileObject) bool {
	if len(manifest.Files) != len(files) {
		return false
	}
	type item struct {
		Size int64
		SHA  string
		Exec bool
		OS   string
	}
	actual := map[string]item{}
	for _, f := range files {
		osv := append([]string(nil), f.TargetOS...)
		sort.Strings(osv)
		actual[f.Path] = item{f.Size, strings.ToLower(f.SHA256), f.Executable, strings.Join(osv, ",")}
	}
	for _, f := range manifest.Files {
		osv := append([]string(nil), f.TargetOS...)
		sort.Strings(osv)
		want, ok := actual[f.Path]
		if !ok || want.Size != f.Size || want.SHA != strings.ToLower(f.SHA256) || want.Exec != f.Executable || want.OS != strings.Join(osv, ",") {
			return false
		}
	}
	return true
}

// prepareAdminPublish0212 preserves the convenient admin publish operation but
// routes it through the same signed/staged/integrity evidence used by the
// canonical package pipeline. Runtime-required policies still require external
// signed runtime evidence before the final publish can proceed.
func (s Server) prepareAdminPublish0212(r *http.Request, release model.ReleaseVersion) (packageLookup, error) {
	if release.Status == "published" {
		return packageLookup{}, errors.New("release уже опубликован; published manifest immutable")
	}
	files, err := s.Repo.ListFiles(release.ProjectID, release.ID)
	if err != nil {
		return packageLookup{}, err
	}
	if len(files) == 0 {
		return packageLookup{}, errors.New("publish требует package files и integrity evidence")
	}
	if s.verifyManifestSignature(release.Manifest) != nil || !manifestFilesMatch0212(release.Manifest, files) {
		manifest := release.Manifest
		manifest.SchemaVersion = "1.0"
		manifest.ProjectID = release.ProjectID
		manifest.ProfileID = release.ProfileID
		manifest.Channel = release.Channel
		manifest.Version = release.Version
		manifest.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		manifest.Files = manifest.Files[:0]
		for _, f := range files {
			manifest.Files = append(manifest.Files, model.ManifestFile{Path: f.Path, Size: f.Size, SHA256: f.SHA256, URL: f.URL, Required: f.Required, Executable: f.Executable, TargetOS: append([]string(nil), f.TargetOS...)})
		}
		if err := validateCompatibilityManifest(manifest); err != nil {
			return packageLookup{}, err
		}
		signed, err := s.signManifest(manifest)
		if err != nil {
			return packageLookup{}, err
		}
		release, err = s.Repo.UpdateVersionManifest(release.ProjectID, release.ID, signed)
		if err != nil {
			return packageLookup{}, err
		}
	}
	if release.Status != "staged" && release.Status != "integrity-passed" {
		if _, err := s.Repo.UpdateVersionStatus(release.ProjectID, release.ID, "staged"); err != nil {
			return packageLookup{}, err
		}
		release.Status = "staged"
	}
	lookup := packageLookup{Release: release, Files: files}
	manifestDigest, err := manifestDigest0212(release.Manifest)
	if err != nil {
		return packageLookup{}, err
	}
	artifactDigest, err := artifactDigest0212(files)
	if err != nil {
		return packageLookup{}, err
	}
	current, err := s.Repo.LatestIntegrityCheck(r.Context(), release.ID)
	if err != nil || current.Result != "passed" || current.ManifestDigest != manifestDigest || current.ArtifactDigest != artifactDigest {
		result, runErr := s.runPackageIntegrityCheck0212(r, lookup)
		if runErr != nil {
			return packageLookup{}, runErr
		}
		if result.Result != "passed" {
			return packageLookup{}, errors.New("package integrity check failed")
		}
	}
	if err := s.validatePublishEvidence0212(r, lookup); err != nil {
		return packageLookup{}, err
	}
	return lookup, nil
}
