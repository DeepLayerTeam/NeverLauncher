package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func distributionFixture04511(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	ver := "0.45.11"
	commit := "1234567890abcdef1234567890abcdef12345678"
	hashes := map[string]string{}
	for _, r := range distributionTargets04511(ver) {
		if err := os.WriteFile(filepath.Join(dir, r.packageFile), []byte("real source-independent test bytes for "+r.target), 0600); err != nil {
			t.Fatal(err)
		}
		h, e := distributionHash04511(dir, r.packageFile)
		if e != nil {
			t.Fatal(e)
		}
		hashes[r.packageFile] = h
	}
	sbomRoots := []sbomPackage{}
	for _, id := range []string{"SPDXRef-Package-CLI", "SPDXRef-Package-BackendAPI", "SPDXRef-Package-Admin", "SPDXRef-Package-Desktop", "SPDXRef-Package-Runtime", "SPDXRef-Package-Bridges"} {
		sbomRoots = append(sbomRoots, sbomPackage{SPDXID: id, Name: id, VersionInfo: ver})
	}
	sbom := map[string]any{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": sbomRoots, "relationships": []sbomRelationship{{SPDXElementID: "SPDXRef-Package-CLI", RelationshipType: "DEPENDS_ON", RelatedSPDXElement: "SPDXRef-Package-BackendAPI"}}}
	if err := bindDistributionSBOM04511(sbom, dir, ver); err != nil {
		t.Fatal(err)
	}
	write := func(name string, data any) {
		t.Helper()
		raw, e := json.Marshal(data)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("SBOM.spdx.json", sbom)
	s, _ := distributionHash04511(dir, "SBOM.spdx.json")
	subjects := []map[string]any{{"name": "SBOM.spdx.json", "digest": map[string]string{"sha256": s}}}
	targets := []map[string]any{}
	for _, r := range distributionTargets04511(ver) {
		subjects = append(subjects, map[string]any{"name": r.packageFile, "digest": map[string]string{"sha256": hashes[r.packageFile]}})
		targets = append(targets, map[string]any{"target": r.target, "package": r.packageFile, "packageSha256": hashes[r.packageFile]})
	}
	materials := []map[string]any{}
	comps := []map[string]string{}
	for _, source := range []string{"cli/go.mod", "services/api/go.mod", "apps/admin/package-lock.json", "apps/desktop/package-lock.json"} {
		digest := fmt.Sprintf("%064x", len(source))
		materials = append(materials, map[string]any{"uri": "file://" + source, "digest": map[string]string{"sha256": digest}})
		comps = append(comps, map[string]string{"sourceFile": source, "sourceSha256": digest})
	}
	write("RELEASE_BOM.json", map[string]any{"components": comps})
	write("PROVENANCE.json", map[string]any{"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://slsa.dev/provenance/v1", "subject": subjects, "predicate": map[string]any{"buildDefinition": map[string]any{"externalParameters": map[string]any{"version": ver, "sourceCommit": commit}, "resolvedDependencies": materials}}})
	write("RELEASE_MANIFEST.json", map[string]any{"version": ver, "sourceCommit": commit})
	write("GA_VERIFIED_TARGETS.json", map[string]any{"version": ver, "commit": commit, "status": "approved-for-release-signing", "targets": targets})
	return dir, ver, commit
}
func TestReleaseDistribution04511ExactSixPackages(t *testing.T) {
	dir, ver, _ := distributionFixture04511(t)
	if err := verifyDistributionSupplyChain04511(dir, ver); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, file string }{
		{"package tampered", distributionTargets04511(ver)[0].packageFile},
		{"spdx removed", "SBOM.spdx.json"},
		{"provenance tampered", "PROVENANCE.json"},
		{"GA approval removed", "GA_VERIFIED_TARGETS.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.file)
			raw, e := os.ReadFile(p)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(p, []byte("changed"), 0600); e != nil {
				t.Fatal(e)
			}
			if e = verifyDistributionSupplyChain04511(dir, ver); e == nil {
				t.Fatal("changed final file passed")
			}
			if e = os.WriteFile(p, raw, 0600); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestReleaseDistribution04511RejectsForgedBindings(t *testing.T) {
	dir, ver, _ := distributionFixture04511(t)
	for _, name := range []string{"SBOM.spdx.json", "PROVENANCE.json", "GA_VERIFIED_TARGETS.json", "RELEASE_MANIFEST.json"} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, name)
			old, e := os.ReadFile(p)
			if e != nil {
				t.Fatal(e)
			}
			var doc map[string]any
			if e = json.Unmarshal(old, &doc); e != nil {
				t.Fatal(e)
			}
			switch name {
			case "SBOM.spdx.json":
				pkgs := doc["packages"].([]any)
				pkg := pkgs[len(pkgs)-1].(map[string]any)
				pkg["checksums"] = []map[string]string{{"algorithm": "SHA256", "checksumValue": "00"}}
			case "PROVENANCE.json":
				pred := doc["predicate"].(map[string]any)
				build := pred["buildDefinition"].(map[string]any)
				build["externalParameters"].(map[string]any)["sourceCommit"] = "0000000000000000000000000000000000000000"
			case "GA_VERIFIED_TARGETS.json":
				doc["targets"].([]any)[0].(map[string]any)["packageSha256"] = "aaaa"
			case "RELEASE_MANIFEST.json":
				doc["sourceCommit"] = "0000000000000000000000000000000000000000"
			}
			raw, _ := json.Marshal(doc)
			if e = os.WriteFile(p, raw, 0600); e != nil {
				t.Fatal(e)
			}
			if e = verifyDistributionSupplyChain04511(dir, ver); e == nil {
				t.Fatalf("tampered %s accepted", name)
			}
			if e = os.WriteFile(p, old, 0600); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestReleaseDistribution04511NotVersionOnly(t *testing.T) {
	dir, ver, _ := distributionFixture04511(t)
	if e := verifyDistributionSupplyChain04511(dir, "0.45.10"); e != nil {
		t.Fatal(e)
	}
	if e := bindDistributionSBOM04511(map[string]any{}, dir, "0.45.10"); e != nil {
		t.Fatal(e)
	}
	if e := verifyDistributionSupplyChain04511(dir, ver); e != nil {
		t.Fatal(fmt.Sprint(e))
	}
}
