package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"go/format"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	cm "gitflic.ru/skif4er/launcher/cli/internal/componentmodel"
)

func fixtureComponents0249(t *testing.T) string {
	t.Helper()
	return "../../../runtime/runtime/tests/fixtures/catalog_actions_0245_go_signed.json"
}
func trustedFixtureKey0249(t *testing.T) string {
	t.Helper()
	raw, e := os.ReadFile(fixtureComponents0249(t))
	if e != nil {
		t.Fatal(e)
	}
	var wire componentsSignedWire0249
	if e = json.Unmarshal(raw, &wire); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "trusted.pub")
	if e = os.WriteFile(path, []byte(wire.Signature.PublicKey), 0600); e != nil {
		t.Fatal(e)
	}
	return path
}
func signWire0249(t *testing.T, w componentsSignedWire0249, priv ed25519.PrivateKey) componentsSignedWire0249 {
	t.Helper()
	w.Signature = nil
	data, e := json.Marshal(w)
	if e != nil {
		t.Fatal(e)
	}
	w.Signature = &componentsSignature0249{Algorithm: "Ed25519", PublicKey: hex.EncodeToString(priv.Public().(ed25519.PublicKey)), Signature: hex.EncodeToString(ed25519.Sign(priv, data)), SignedAt: "2026-10-20T12:00:00Z"}
	return w
}
func writeWire0249(t *testing.T, w componentsSignedWire0249) string {
	t.Helper()
	data, e := json.MarshalIndent(w, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(t.TempDir(), "manifest.json")
	if e = os.WriteFile(file, data, 0600); e != nil {
		t.Fatal(e)
	}
	return file
}
func TestCLIComponentsValidSignedManifestAndDeterminism0249(t *testing.T) {
	src, key := fixtureComponents0249(t), trustedFixtureKey0249(t)
	entry, e := loadComponents0249(src, key, false)
	if e != nil || !entry.SignatureVerified {
		t.Fatalf("real Go-signed fixture: %v", e)
	}
	if _, e = loadComponents0249(src, "", false); e == nil {
		t.Fatal("missing trust root accepted")
	}
	if _, e = loadComponents0249(src, key, true); e != nil {
		t.Fatalf("explicit local override: %v", e)
	}
	env := cm.ComponentEnvironment0244{OS: "linux", Arch: "x86_64", JavaMajor: 21, MinecraftVersion: "1.21.1", Loader: "fabric", LoaderVersion: "0.16.1"}
	plan, e := resolveComponents0249(entry, "quality", env)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(plan.Components, []string{"core", "performance.sodium", "shaders"}) || plan.DownloadBytes != 9 {
		t.Fatalf("bad resolved plan %+v", plan)
	}
	if plan.Reasons[1].Reason != "dependency" || plan.Reasons[1].Via != "shaders" || len(plan.Actions) != 4 {
		t.Fatalf("missing explanations/actions: %+v", plan)
	}
	other, e := resolveComponents0249(entry, "quality", env)
	if e != nil || plan.PlanSHA256 != other.PlanSHA256 {
		t.Fatal("nondeterministic resolver")
	}
	if _, e = resolveComponents0249(entry, "quality", cm.ComponentEnvironment0244{OS: "windows", Arch: "x86_64"}); e == nil || !strings.Contains(e.Error(), "condition_unsatisfied") {
		t.Fatalf("invalid environment accepted: %v", e)
	}
	output := filepath.Join(t.TempDir(), "report.json")
	args := []string{"components", "resolve", "--manifest", src, "--public-key", key, "--preset", "quality", "--os", "linux", "--arch", "x86_64", "--java-major", "21", "--minecraft", "1.21.1", "--loader", "fabric", "--loader-version", "0.16.1", "--output", output}
	if e = run(args); e != nil {
		t.Fatal(e)
	}
	first, e := os.ReadFile(output)
	if e != nil {
		t.Fatal(e)
	}
	if e = run(args); e != nil {
		t.Fatal(e)
	}
	second, _ := os.ReadFile(output)
	if !bytes.Equal(first, second) {
		t.Fatal("non-deterministic JSON")
	}
	if e = run([]string{"components", "validate", "--manifest", src, "--public-key", key, "--output", output}); e != nil {
		t.Fatal(e)
	}
	if e = run([]string{"components", "export", "--manifest", src, "--public-key", key, "--output", output}); e != nil {
		t.Fatal(e)
	}
}
func TestCLIComponentsRejectTamperingAndDiff0249(t *testing.T) {
	src := fixtureComponents0249(t)
	raw, e := os.ReadFile(src)
	if e != nil {
		t.Fatal(e)
	}
	var wire componentsSignedWire0249
	if e = json.Unmarshal(raw, &wire); e != nil {
		t.Fatal(e)
	}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	key := filepath.Join(t.TempDir(), "key.pub")
	if e = os.WriteFile(key, []byte(hex.EncodeToString(pub)), 0600); e != nil {
		t.Fatal(e)
	}
	before := writeWire0249(t, signWire0249(t, wire, priv))
	if _, e = loadComponents0249(before, key, false); e != nil {
		t.Fatal(e)
	}
	var manifest cm.Manifest
	if e = json.Unmarshal(raw, &manifest); e != nil {
		t.Fatal(e)
	}
	manifest.ComponentCatalog.Components[2].Description = "Enhanced shader preset"
	manifest.ComponentCatalog.Digest = cm.ComponentCatalogDigest0245(*manifest.ComponentCatalog)
	nextCatalog, e := json.Marshal(manifest.ComponentCatalog)
	if e != nil {
		t.Fatal(e)
	}
	wire.ComponentCatalog = nextCatalog
	after := writeWire0249(t, signWire0249(t, wire, priv))
	if _, e = loadComponents0249(after, key, false); e != nil {
		t.Fatal(e)
	}
	output := filepath.Join(t.TempDir(), "diff.json")
	if e = run([]string{"components", "diff", "--old", before, "--new", after, "--public-key", key, "--old-preset", "minimal", "--preset", "quality", "--os", "linux", "--arch", "x86_64", "--java-major", "21", "--minecraft", "1.21.1", "--loader", "fabric", "--loader-version", "0.16.1", "--output", output}); e != nil {
		t.Fatal(e)
	}
	contents, e := os.ReadFile(output)
	if e != nil {
		t.Fatal(e)
	}
	var diff struct {
		Verified          bool                 `json:"signatureVerified"`
		ChangedComponents []string             `json:"changedComponents"`
		AddedFiles        []componentsFile0249 `json:"addedFiles"`
	}
	if e = json.Unmarshal(contents, &diff); e != nil {
		t.Fatal(e)
	}
	if !diff.Verified || !reflect.DeepEqual(diff.ChangedComponents, []string{"shaders"}) || len(diff.AddedFiles) != 3 {
		t.Fatalf("invalid component diff: %s", contents)
	}
	// A tampered signed payload must be rejected even when its catalog digest is valid.
	wire.ComponentCatalog = json.RawMessage(strings.Replace(string(nextCatalog), "Enhanced shader preset", "Tampered", 1))
	tampered := writeWire0249(t, wire)
	if _, e = loadComponents0249(tampered, key, false); e == nil {
		t.Fatal("signature bypass")
	}
	// Explicit draft mode does not bypass catalog digest validation.
	if _, e = loadComponents0249(tampered, "", true); e == nil {
		t.Fatal("digest bypass")
	}
	// An attacker with a self-declared signing key must not be trusted.
	randomKey := filepath.Join(t.TempDir(), "other.pub")
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	os.WriteFile(randomKey, []byte(hex.EncodeToString(other)), 0600)
	if _, e = loadComponents0249(before, randomKey, false); e == nil {
		t.Fatal("self-signed untrusted manifest accepted")
	}
}

func TestCLIComponentsEngineParity0249(t *testing.T) {
	for _, name := range []string{"component_catalog_0241.go", "component_resolver_0243.go", "component_conditions_0244.go", "component_actions_0245.go"} {
		original, e := os.ReadFile("../../../services/api/internal/model/" + name)
		if e != nil {
			t.Fatal(e)
		}
		cli, e := os.ReadFile("../../internal/componentmodel/" + name)
		if e != nil {
			t.Fatal(e)
		}
		formatted, e := format.Source([]byte(strings.Replace(string(original), "package model", "package componentmodel", 1)))
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(formatted, cli) {
			t.Fatalf("CLI engine drift from Backend: %s", name)
		}
	}
}
func TestCLIComponentsRejectDuplicateKeysAndEmitJSONErrors0249(t *testing.T) {
	if e := rejectDuplicateJSON0249([]byte(`{"x":{"a":1,"a":2}}`)); e == nil {
		t.Fatal("duplicate JSON key accepted")
	}
	if e := rejectDuplicateJSON0249([]byte(`{"x":[1,{"b":2}]}`)); e != nil {
		t.Fatal(e)
	}
	src := fixtureComponents0249(t)
	key := trustedFixtureKey0249(t)
	out := filepath.Join(t.TempDir(), "error.json")
	err := run([]string{"components", "resolve", "--manifest", src, "--public-key", key, "--preset", "does-not-exist", "--output", out})
	if err == nil {
		t.Fatal("unknown preset accepted")
	}
	raw, e := os.ReadFile(out)
	if e != nil {
		t.Fatal(e)
	}
	var report struct {
		Status string `json:"status"`
		Code   string `json:"code"`
	}
	if e = json.Unmarshal(raw, &report); e != nil {
		t.Fatal(e)
	}
	if report.Status != "error" || report.Code != "unknown_preset" {
		t.Fatalf("invalid structured error: %s", raw)
	}
}
