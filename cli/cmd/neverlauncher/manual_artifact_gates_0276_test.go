package main

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func artifactPack0276(t *testing.T, server *httptest.Server, mod []byte, withDownload bool) string {
	t.Helper()
	sum := sha512.Sum512(mod)
	urls := []string{}
	if withDownload {
		urls = []string{server.URL + "/mod.jar"}
	}
	index := map[string]any{"formatVersion": 1, "game": "minecraft", "versionId": "1.0", "name": "Gated Test", "dependencies": map[string]string{"minecraft": "fixture-1"}, "files": []any{map[string]any{"path": "mods/test.jar", "hashes": map[string]string{"sha1": sha1hex(mod), "sha512": hex.EncodeToString(sum[:])}, "downloads": urls, "fileSize": len(mod)}}}
	raw, e := json.Marshal(index)
	if e != nil {
		t.Fatal(e)
	}
	return packFixtureZip0275(t, map[string][]byte{"modrinth.index.json": raw, "overrides/config/settings.txt": []byte("local config")})
}
func permissionsFor0276(t *testing.T, pack string, files []modpackFile0275) string {
	t.Helper()
	hash, _, e := hashFile(pack)
	if e != nil {
		t.Fatal(e)
	}
	policy := artifactPermissions0276{SchemaVersion: permissionSchema0276, PackSHA256: hash}
	for _, f := range files {
		policy.Grants = append(policy.Grants, artifactGrant0276{Path: f.Path, SHA256: f.SHA256, Right: "redistribute", EvidenceURL: "https://example.org/licenses/consent", AuthorizedBy: "Copyright owner (operator assertion)"})
	}
	raw, e := json.Marshal(policy)
	if e != nil {
		t.Fatal(e)
	}
	loc := filepath.Join(t.TempDir(), "permissions.json")
	if e = os.WriteFile(loc, raw, 0600); e != nil {
		t.Fatal(e)
	}
	return loc
}
func TestManualGates0276LocalInstallAndExportRequiresExactGrants(t *testing.T) {
	mod := []byte("mod-content-fixture")
	srv := fixtureModpackServer0275(t, mod)
	defer srv.Close()
	pack := artifactPack0276(t, srv, mod, true)
	dir := filepath.Join(t.TempDir(), "client")
	receipt, err := importModpack0275(context.Background(), pack, dir, "", "", "", false, fixtureModpackOptions0275(srv))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "complete" || len(receipt.Imported) != 2 {
		t.Fatalf("invalid receipt %+v", receipt)
	}
	if receipt.Imported[0].SHA256 == "" {
		t.Fatal("hash absent")
	}
	report, _, err := evaluatePublishedArtifacts0276(dir, "")
	if err != nil || report.Status != "blocked" || len(report.Missing) != 1 || report.Missing[0].Code != "permissions_unavailable" {
		t.Fatalf("default must block release: %+v %v", report, err)
	}
	policy := permissionsFor0276(t, pack, receipt.Imported[:1])
	report, _, err = evaluatePublishedArtifacts0276(dir, policy)
	if err != nil || report.Status != "blocked" || len(report.Missing) != 1 || report.Missing[0].Code != "redistribution_not_authorized" {
		t.Fatalf("missing file permission must block: %+v %v", report, err)
	}
	policy = permissionsFor0276(t, pack, receipt.Imported)
	report, _, err = evaluatePublishedArtifacts0276(dir, policy)
	if err != nil || report.Status != "ready" || report.Checked != 2 || report.Authorized != 2 {
		t.Fatalf("unexpected pass %+v %v", report, err)
	}
	export := filepath.Join(t.TempDir(), "artifacts.zip")
	report, err = exportModpackArtifacts0276(dir, policy, export)
	if err != nil || report.Status != "ready" {
		t.Fatalf("export failed: %+v %v", report, err)
	}
	zr, e := zip.OpenReader(export)
	if e != nil {
		t.Fatal(e)
	}
	defer zr.Close()
	entries := map[string]bool{}
	for _, f := range zr.File {
		entries[f.Name] = true
	}
	if !entries["files/mods/test.jar"] || !entries["files/config/settings.txt"] || !entries["artifact-bundle.json"] || len(entries) != 3 {
		t.Fatalf("not an artifact-only export: %+v", entries)
	}
	if _, e = os.Stat(filepath.Join(dir, "versions")); e != nil {
		t.Fatal("should not modify installed client", e)
	}
	if _, e = exportModpackArtifacts0276(dir, policy, export); e == nil {
		t.Fatal("must not overwrite existing export")
	}
	if e = os.WriteFile(filepath.Join(dir, "mods/test.jar"), []byte("tampered"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, e = evaluatePublishedArtifacts0276(dir, policy); e == nil {
		t.Fatal("tampered lock must prevent export")
	}
}
func TestManualGates0276FailClosedDuringImportAndVerifiedManual(t *testing.T) {
	mod := []byte("manual-verified-mod")
	srv := fixtureModpackServer0275(t, mod)
	defer srv.Close()
	pack := artifactPack0276(t, srv, mod, false)
	manual := t.TempDir()
	if e := os.MkdirAll(filepath.Join(manual, "mods"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(manual, "mods/test.jar"), mod, 0600); e != nil {
		t.Fatal(e)
	}
	root := t.TempDir()
	target := filepath.Join(root, "client")
	report, err := importModpackWithGates0276(context.Background(), pack, target, manual, "", "", false, fixtureModpackOptions0275(srv), "", "redistributable")
	if err == nil || report.Status != "blocked" || len(report.Missing) != 1 || report.Missing[0].Code != "permissions_unavailable" {
		t.Fatalf("redistributable import must block: %+v %v", report, err)
	}
	if _, e := os.Stat(target); !os.IsNotExist(e) {
		t.Fatal("partial output published")
	}
	bytesHash := sha256.Sum256(mod)
	config := sha256.Sum256([]byte("local config"))
	policy := permissionsFor0276(t, pack, []modpackFile0275{{Path: "mods/test.jar", SHA256: hex.EncodeToString(bytesHash[:])}, {Path: "config/settings.txt", SHA256: hex.EncodeToString(config[:])}})
	report, err = importModpackWithGates0276(context.Background(), pack, target, manual, "", "", false, fixtureModpackOptions0275(srv), policy, "redistributable")
	if err != nil || report.Status != "complete" {
		t.Fatalf("verified manual import failed: %+v %v", report, err)
	}
	if len(report.Imported) != 2 {
		t.Fatal("missing outputs")
	}
	var found bool
	for _, f := range report.Imported {
		if f.Path == "mods/test.jar" {
			found = f.Acquisition == "manual-verified"
		}
	}
	if !found {
		t.Fatalf("missing manual provenance: %+v", report.Imported)
	}
	gate, _, err := evaluatePublishedArtifacts0276(target, policy)
	if err != nil || gate.Status != "ready" {
		t.Fatalf("gate failed: %+v %v", gate, err)
	}
}
func TestManualGates0276StructuredMissingAndSymlink(t *testing.T) {
	mod := []byte("expected")
	srv := fixtureModpackServer0275(t, mod)
	defer srv.Close()
	pack := artifactPack0276(t, srv, mod, false)
	dir := t.TempDir()
	target := filepath.Join(dir, "client")
	report, err := importModpack0275(context.Background(), pack, target, "", "", "", false, fixtureModpackOptions0275(srv))
	if err == nil || report.Status != "blocked" || len(report.Missing) != 1 {
		t.Fatalf("missing file must block: %+v %v", report, err)
	}
	missing := report.Missing[0]
	if missing.Code != "manual_required" || !missing.CanManual || missing.ExpectedSHA1 == "" || missing.ExpectedSHA512 == "" || missing.ExpectedSize != int64(len(mod)) {
		t.Fatalf("missing action not actionable: %+v", missing)
	}
	root := filepath.Join(dir, "manual")
	if e := os.MkdirAll(root, 0700); e != nil {
		t.Fatal(e)
	}
	outside := filepath.Join(dir, "outside.jar")
	if e := os.WriteFile(outside, mod, 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(root, "test.jar")
	if e := os.Symlink(outside, link); e != nil {
		t.Skipf("symlink unavailable: %v", e)
	}
	if _, e := secureManualSource0276(root, "test.jar"); e == nil {
		t.Fatal("symlink was followed")
	}
}
func TestManualGates0276RejectPolicyMutationAndInvalidInput(t *testing.T) {
	p := artifactPermissions0276{SchemaVersion: permissionSchema0276, PackSHA256: strings.Repeat("a", 64), Grants: []artifactGrant0276{{Path: "mods/a.jar", SHA256: strings.Repeat("b", 64), Right: "redistribute", EvidenceURL: "https://example.org/license", AuthorizedBy: "Owner"}}}
	file := filepath.Join(t.TempDir(), "permissions.json")
	for label, mutate := range map[string]func(*artifactPermissions0276){
		"http evidence":      func(p *artifactPermissions0276) { p.Grants[0].EvidenceURL = "http://localhost/license" },
		"wrong right":        func(p *artifactPermissions0276) { p.Grants[0].Right = "download" },
		"wrong hash":         func(p *artifactPermissions0276) { p.Grants[0].SHA256 = "invalid" },
		"missing authorizer": func(p *artifactPermissions0276) { p.Grants[0].AuthorizedBy = "" },
		"duplicate":          func(p *artifactPermissions0276) { p.Grants = append(p.Grants, p.Grants[0]) },
		"escape":             func(p *artifactPermissions0276) { p.Grants[0].Path = "../outside.jar" },
	} {
		t.Run(label, func(t *testing.T) {
			value := p
			value.Grants = append([]artifactGrant0276(nil), p.Grants...)
			mutate(&value)
			raw, _ := json.Marshal(value)
			if e := os.WriteFile(file, raw, 0600); e != nil {
				t.Fatal(e)
			}
			if _, e := readArtifactPermissions0276(file); e == nil {
				t.Fatal("accepted unsafe grant")
			}
		})
	}
	raw, _ := json.Marshal(p)
	if e := os.WriteFile(file, append(raw, []byte(` {"bad":true}`)...), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := readArtifactPermissions0276(file); e == nil {
		t.Fatal("accepted trailing JSON")
	}
	r := verifyPermissionGrants0276(strings.Repeat("c", 64), "", nil, p)
	if r.Status != "blocked" || len(r.Missing) != 1 || r.Missing[0].Code != "pack_identity_mismatch" {
		t.Fatalf("accepted wrong pack: %+v", r)
	}
}

func TestManualGates0276RealCLICommands(t *testing.T) {
	mod := []byte("cli-test-mod")
	srv := fixtureModpackServer0275(t, mod)
	defer srv.Close()
	pack := artifactPack0276(t, srv, mod, true)
	root := t.TempDir()
	clientDir := filepath.Join(root, "client")
	receipt, e := importModpack0275(context.Background(), pack, clientDir, "", "", "", false, fixtureModpackOptions0275(srv))
	if e != nil {
		t.Fatal(e)
	}
	rightsReport := filepath.Join(root, "rights.json")
	// Non-zero exit on missing rights while still persisting a machine-readable report.
	e = handleRuntimeFactory0271([]string{"verify-publication", "--client-dir", clientDir, "--output", rightsReport})
	if e == nil {
		t.Fatal("CLI gate returned success without rights")
	}
	b, e := os.ReadFile(rightsReport)
	if e != nil {
		t.Fatal(e)
	}
	var denied permissionGateReport0276
	if e = json.Unmarshal(b, &denied); e != nil || denied.Status != "blocked" {
		t.Fatalf("missing blocked CLI report: %+v %v", denied, e)
	}
	policy := permissionsFor0276(t, pack, receipt.Imported)
	if e = handleRuntimeFactory0271([]string{"verify-publication", "--client-dir", clientDir, "--permissions-file", policy, "--output", rightsReport}); e != nil {
		t.Fatal(e)
	}
	var ready permissionGateReport0276
	b, e = os.ReadFile(rightsReport)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &ready); e != nil || ready.Status != "ready" {
		t.Fatalf("gate not ready: %+v %v", ready, e)
	}
	export := filepath.Join(root, "export.zip")
	if e = handleRuntimeFactory0271([]string{"export-modpack-artifacts", "--client-dir", clientDir, "--permissions-file", policy, "--file", export, "--output", rightsReport}); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(export); e != nil {
		t.Fatal("CLI did not export artifact ZIP", e)
	}
}
