package main

// Manual Artifacts & Permission Gates. A verified local acquisition is not a
// grant to redistribute third-party files. The distribution operation has its
// own fail-closed gate, bound to the import receipt, the exact content digest,
// and an explicit operator-supplied rights record. No Minecraft binaries or
// loader libraries are ever included in the exported artifact-only overlay.
import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const permissionSchema0276 = "neverlauncher.artifact-permissions.v1"

type artifactGrant0276 struct {
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	Right        string `json:"right"`
	EvidenceURL  string `json:"evidenceUrl"`
	AuthorizedBy string `json:"authorizedBy"`
}
type artifactPermissions0276 struct {
	SchemaVersion string              `json:"schemaVersion"`
	PackSHA256    string              `json:"packSha256"`
	Grants        []artifactGrant0276 `json:"grants"`
}
type permissionGateReport0276 struct {
	SchemaVersion string               `json:"schemaVersion"`
	PackSHA256    string               `json:"packSha256"`
	PlanSHA256    string               `json:"planSha256,omitempty"`
	Status        string               `json:"status"`
	Checked       int                  `json:"checked"`
	Authorized    int                  `json:"authorized"`
	Missing       []modpackMissing0275 `json:"missing,omitempty"`
}

func validSHA2560276(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}

func readArtifactPermissions0276(file string) (artifactPermissions0276, error) {
	var p artifactPermissions0276
	if file == "" {
		return p, errors.New("--permissions-file required for redistribution")
	}
	st, err := os.Lstat(file)
	if err != nil {
		return p, err
	}
	if !st.Mode().IsRegular() || st.Size() > 4<<20 {
		return p, errors.New("permissions file must be a regular JSON file <= 4MiB")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return p, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&p); err != nil {
		return p, err
	}
	if err = dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return p, errors.New("extra JSON after permissions")
	}
	if p.SchemaVersion != permissionSchema0276 || !validSHA2560276(p.PackSHA256) {
		return p, errors.New("unsupported permission schema or invalid pack SHA256")
	}
	if len(p.Grants) > 4000 {
		return p, errors.New("too many permission grants")
	}
	unique := map[string]bool{}
	for _, g := range p.Grants {
		if err = packOutputPath0275(g.Path); err != nil {
			return p, err
		}
		if !validSHA2560276(g.SHA256) || g.Right != "redistribute" {
			return p, fmt.Errorf("invalid right or SHA256 for %q", g.Path)
		}
		if g.AuthorizedBy == "" || len(g.AuthorizedBy) > 256 || strings.TrimSpace(g.AuthorizedBy) != g.AuthorizedBy {
			return p, fmt.Errorf("missing authorizing party for %q", g.Path)
		}
		if err = validateRemoteURL(g.EvidenceURL); err != nil {
			return p, fmt.Errorf("%s: evidence URL: %w", g.Path, err)
		}
		u, _ := url.Parse(g.EvidenceURL)
		if u.Scheme != "https" {
			return p, fmt.Errorf("%s: evidence URL must be HTTPS", g.Path)
		}
		if unique[strings.ToLower(g.Path)] {
			return p, fmt.Errorf("duplicate permission entry for %q", g.Path)
		}
		unique[strings.ToLower(g.Path)] = true
	}
	return p, nil
}

func verifyPermissionGrants0276(packSHA, planSHA string, files []modpackFile0275, p artifactPermissions0276) permissionGateReport0276 {
	report := permissionGateReport0276{SchemaVersion: permissionSchema0276, PackSHA256: packSHA, PlanSHA256: planSHA, Status: "blocked", Checked: len(files)}
	if p.PackSHA256 != packSHA {
		report.Missing = append(report.Missing, modpackMissing0275{Code: "pack_identity_mismatch", Path: "manifest", Source: "permissions", Reason: "permission record is for a different modpack ZIP", ManualAction: "provide permission grants tied to the exact packSha256"})
		return report
	}
	grants := make(map[string]artifactGrant0276, len(p.Grants))
	for _, grant := range p.Grants {
		grants[strings.ToLower(grant.Path)] = grant
	}
	for _, file := range files {
		grant, ok := grants[strings.ToLower(file.Path)]
		if !ok || grant.Path != file.Path || grant.SHA256 != file.SHA256 {
			report.Missing = append(report.Missing, modpackMissing0275{Code: "redistribution_not_authorized", Path: file.Path, Source: file.Source, Reason: "missing exact SHA256-bound redistribution authorization", ManualAction: "obtain rights from the copyright owner and supply a matching permission record", ExpectedSHA256: file.SHA256, ExpectedSize: file.Size})
			continue
		}
		report.Authorized++
	}
	if len(report.Missing) == 0 {
		report.Status = "ready"
	}
	return report
}

func readModpackReceipt0276(dir string) (modpackReport0275, factoryPlan0271, error) {
	var report modpackReport0275
	p, err := readFactoryPlan0271(dir)
	if err != nil {
		return report, p, err
	}
	if err = verifyFactoryPlan0271(dir, p); err != nil {
		return report, p, err
	}
	receipt := filepath.Join(dir, filepath.FromSlash(modpackEvidencePath0275))
	st, err := os.Lstat(receipt)
	if err != nil {
		return report, p, err
	}
	if !st.Mode().IsRegular() || st.Size() > 4<<20 {
		return report, p, errors.New("invalid modpack receipt")
	}
	b, err := os.ReadFile(receipt)
	if err != nil {
		return report, p, err
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&report); err != nil {
		return report, p, err
	}
	if err = decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return report, p, errors.New("extra receipt JSON")
	}
	if report.Status != "complete" || !validSHA2560276(report.PackSHA256) || len(report.Imported) > 4000 {
		return report, p, errors.New("incomplete or invalid modpack import receipt")
	}
	found := map[string]factoryOutput0271{}
	for _, out := range p.Outputs {
		found[out.Path] = out
	}
	seen := map[string]bool{}
	for _, f := range report.Imported {
		if err := packOutputPath0275(f.Path); err != nil {
			return report, p, err
		}
		if !validSHA2560276(f.SHA256) || f.Source == "" || seen[strings.ToLower(f.Path)] {
			return report, p, fmt.Errorf("invalid or duplicate receipt artifact %q", f.Path)
		}
		seen[strings.ToLower(f.Path)] = true
		out, ok := found[f.Path]
		if !ok || out.SHA256 != f.SHA256 || out.Size != f.Size {
			return report, p, fmt.Errorf("import receipt does not match locked output %s", f.Path)
		}
	}
	return report, p, nil
}

func evaluatePublishedArtifacts0276(dir, permissionsFile string) (permissionGateReport0276, []modpackFile0275, error) {
	receipt, p, err := readModpackReceipt0276(dir)
	if err != nil {
		return permissionGateReport0276{}, nil, err
	}
	permissions, err := readArtifactPermissions0276(permissionsFile)
	if err != nil {
		return permissionGateReport0276{SchemaVersion: permissionSchema0276, PackSHA256: receipt.PackSHA256, PlanSHA256: p.ReproducibilitySHA256, Status: "blocked", Checked: len(receipt.Imported), Missing: []modpackMissing0275{{Code: "permissions_unavailable", Path: "permissions", Source: "permissions", Reason: err.Error(), ManualAction: "provide exact SHA256-bound --permissions-file"}}}, receipt.Imported, nil
	}
	result := verifyPermissionGrants0276(receipt.PackSHA256, p.ReproducibilitySHA256, receipt.Imported, permissions)
	return result, receipt.Imported, nil
}

func exportModpackArtifacts0276(dir, permissionsFile, output string) (permissionGateReport0276, error) {
	result, files, err := evaluatePublishedArtifacts0276(dir, permissionsFile)
	if err != nil {
		return result, err
	}
	if result.Status != "ready" {
		return result, fmt.Errorf("%d artifact permissions missing; export blocked", len(result.Missing))
	}
	if output == "" {
		return result, errors.New("--file export output ZIP required")
	}
	if err = rejectFactoryOutputPath0271(dir, output); err != nil {
		return result, err
	}
	if _, e := os.Lstat(output); e == nil {
		return result, errors.New("export output already exists")
	} else if !errors.Is(e, os.ErrNotExist) {
		return result, e
	}
	parent := filepath.Dir(output)
	if err = os.MkdirAll(parent, 0755); err != nil {
		return result, err
	}
	tmp, err := os.CreateTemp(parent, ".modpack-artifacts-*.zip")
	if err != nil {
		return result, err
	}
	defer os.Remove(tmp.Name())
	w := zip.NewWriter(tmp)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	fail := func(err error) (permissionGateReport0276, error) { _ = w.Close(); _ = tmp.Close(); return result, err }
	// Artifact-only export: excludes Minecraft runtime, Mojang assets, and loader binaries.
	for _, item := range files {
		src, e := secureClientDestination(dir, item.Path)
		if e != nil {
			return fail(e)
		}
		st, e := os.Lstat(src)
		if e != nil || !st.Mode().IsRegular() {
			return fail(fmt.Errorf("export source not regular: %s", item.Path))
		}
		in, e := os.Open(src)
		if e != nil {
			return fail(e)
		}
		out, e := w.Create("files/" + item.Path)
		if e != nil {
			_ = in.Close()
			return fail(e)
		}
		digest := sha256.New()
		n, e := io.Copy(io.MultiWriter(out, digest), io.LimitReader(in, modpackMaxFile0275+1))
		_ = in.Close()
		if e != nil || n != item.Size || hex.EncodeToString(digest.Sum(nil)) != item.SHA256 {
			return fail(fmt.Errorf("source changed during export: %s", item.Path))
		}
	}
	meta, e := w.Create("artifact-bundle.json")
	if e != nil {
		return fail(e)
	}
	manifest := struct {
		SchemaVersion     string            `json:"schemaVersion"`
		PackSHA256        string            `json:"packSha256"`
		InstallPlanSHA256 string            `json:"installPlanSha256"`
		Files             []modpackFile0275 `json:"files"`
		// Human-declared provenance, not independent verification of licensing.
		DeclaredRights []artifactGrant0276 `json:"declaredRights"`
	}{SchemaVersion: "neverlauncher.modpack-artifact-bundle.v1", PackSHA256: result.PackSHA256, InstallPlanSHA256: result.PlanSHA256, Files: files}
	grants, _ := readArtifactPermissions0276(permissionsFile)
	manifest.DeclaredRights = grants.Grants
	sort.Slice(manifest.DeclaredRights, func(i, j int) bool { return manifest.DeclaredRights[i].Path < manifest.DeclaredRights[j].Path })
	if e = json.NewEncoder(meta).Encode(manifest); e != nil {
		return fail(e)
	}
	if e = w.Close(); e != nil {
		_ = tmp.Close()
		return result, e
	}
	if e = tmp.Sync(); e != nil {
		_ = tmp.Close()
		return result, e
	}
	if e = tmp.Close(); e != nil {
		return result, e
	}
	// Link is atomic and refuses to overwrite an existing export, including
	// one created by another writer while we were preparing this ZIP.
	if err = os.Link(tmp.Name(), output); err != nil {
		return result, err
	}
	return result, nil
}

func handlePermissionGates0276(args []string) error {
	if len(args) == 0 {
		return errors.New("verify-publication|export-modpack-artifacts")
	}
	flags := args[1:]
	dir := flagValue(flags, "--client-dir", "")
	if dir == "" {
		return errors.New("--client-dir required")
	}
	permissions := flagValue(flags, "--permissions-file", "")
	output := flagValue(flags, "--output", "")
	if err := rejectFactoryOutputPath0271(dir, output); err != nil {
		return err
	}
	var report permissionGateReport0276
	var err error
	switch args[0] {
	case "verify-publication":
		report, _, err = evaluatePublishedArtifacts0276(dir, permissions)
	case "export-modpack-artifacts":
		report, err = exportModpackArtifacts0276(dir, permissions, flagValue(flags, "--file", ""))
	default:
		return errors.New("unknown permission gate command")
	}
	if err2 := writeOrPrintJSON(output, report); err2 != nil {
		return err2
	}
	if report.Status == "blocked" {
		return fmt.Errorf("%d redistribution permission gates failed", len(report.Missing))
	}
	return err
}

func missingModpackArtifact0276(f modpackFile0275, cause error) modpackMissing0275 {
	message := cause.Error()
	code := "download_failed"
	switch {
	case strings.Contains(message, "no permitted download URL"):
		code = "manual_required"
	case strings.Contains(message, "HTTP 403") || strings.Contains(message, "HTTP 451"):
		code = "download_forbidden"
	case strings.Contains(message, "SHA-") || strings.Contains(message, "size mismatch"):
		code = "checksum_mismatch"
	}
	return modpackMissing0275{Code: code, Path: f.Path, Source: f.Source, Reason: message, ManualAction: "provide a rights-compliant source or --manual-dir artifact matching the upstream hashes", ExpectedSHA1: f.SHA1, ExpectedSHA512: f.SHA512, ExpectedSHA256: f.SHA256, ExpectedSize: f.Size, CanManual: f.SHA1 != "" || f.SHA512 != "" || f.SHA256 != ""}
}

// Resolve manual files without following symlink directories or symlink files.
// The operator-supplied folder itself must be a real directory.
func secureManualSource0276(root, rel string) (string, error) {
	if err := packOutputPath0275(rel); err != nil {
		return "", err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	parts := append([]string{abs}, strings.Split(rel, "/")...)
	cur := parts[0]
	base, e := os.Lstat(cur)
	if e != nil {
		return "", e
	}
	if !base.IsDir() || base.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("manual directory is not a real directory")
	}
	for i, segment := range parts[1:] {
		cur = filepath.Join(cur, segment)
		st, e := os.Lstat(cur)
		if e != nil {
			return "", e
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("manual source symlink forbidden")
		}
		if i == len(parts)-2 {
			if !st.Mode().IsRegular() {
				return "", errors.New("manual artifact not regular")
			}
		} else if !st.IsDir() {
			return "", errors.New("manual parent not a directory")
		}
	}
	return cur, nil
}
