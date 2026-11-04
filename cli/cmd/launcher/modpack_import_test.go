package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func packFixtureZip0275(t *testing.T, names map[string][]byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fixture.mrpack")
	f, e := os.Create(p)
	if e != nil {
		t.Fatal(e)
	}
	w := zip.NewWriter(f)
	for name, body := range names {
		entry, e := w.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = entry.Write(body); e != nil {
			t.Fatal(e)
		}
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	return p
}
func fixtureModpackServer0275(t *testing.T, modBytes []byte) *httptest.Server {
	t.Helper()
	asset := []byte("fixture-pack-asset")
	clientJar := []byte("fixture-pack-client")
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		meta := fixtureFactoryMetadata0271(base, "fixture-1", clientJar, asset)
		switch r.URL.Path {
		case "/manifest.json":
			_ = json.NewEncoder(w).Encode(MojangVersionManifest{Latest: map[string]string{"release": "fixture-1"}, Versions: []MojangManifestVersion{{ID: "fixture-1", Type: "release", URL: base + "/version.json", SHA1: sha1hex(meta)}}})
		case "/version.json":
			w.Write(meta)
		case "/client.jar":
			w.Write(clientJar)
		case "/asset-index.json":
			w.Write(fixtureFactoryAssets0271(asset))
		case "/assets/" + sha1hex(asset)[:2] + "/" + sha1hex(asset):
			w.Write(asset)
		case "/mod.jar":
			w.Write(modBytes)
		case "/v1/mods/101/files/202":
			if r.Header.Get("x-api-key") != "test-api-key" {
				w.WriteHeader(403)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": 202, "modId": 101, "fileName": "cfmod.jar", "fileLength": len(modBytes), "downloadUrl": nil, "hashes": []any{map[string]any{"value": sha1hex(modBytes), "algo": 1}}}})
		case "/v1/mods/101/files/202/download-url":
			if r.Header.Get("x-api-key") != "test-api-key" {
				w.WriteHeader(403)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": base + "/mod.jar"})
		default:
			http.NotFound(w, r)
		}
	}))
	return server
}
func fixtureModpackOptions0275(s *httptest.Server) factoryBuildOptions0271 {
	return factoryBuildOptions0271{VersionManifest: s.URL + "/manifest.json", AssetBaseURL: s.URL + "/assets", Workers: 2, StrictUpstream: true}
}
func TestModpack0275ModrinthImportClientOverridesAndVerify(t *testing.T) {
	mod := []byte("modrinth-fixture-jar")
	h512 := sha512.Sum512(mod)
	server := fixtureModpackServer0275(t, mod)
	defer server.Close()
	index := map[string]any{"formatVersion": 1, "game": "minecraft", "versionId": "1.0", "name": "Fixture Pack", "dependencies": map[string]string{"minecraft": "fixture-1"}, "files": []any{map[string]any{"path": "mods/a.jar", "hashes": map[string]string{"sha1": sha1hex(mod), "sha512": hex.EncodeToString(h512[:])}, "downloads": []string{server.URL + "/mod.jar"}, "fileSize": len(mod), "env": map[string]string{"client": "required", "server": "unsupported"}}, map[string]any{"path": "mods/server.jar", "hashes": map[string]string{"sha1": sha1hex(mod), "sha512": hex.EncodeToString(h512[:])}, "downloads": []string{server.URL + "/mod.jar"}, "fileSize": len(mod), "env": map[string]string{"client": "unsupported", "server": "required"}}}}
	raw, _ := json.Marshal(index)
	archive := packFixtureZip0275(t, map[string][]byte{"modrinth.index.json": raw, "overrides/config/feature.cfg": []byte("base"), "client-overrides/config/feature.cfg": []byte("client"), "server-overrides/config/server.cfg": []byte("server")})
	dest := filepath.Join(t.TempDir(), "client")
	report, err := importModpack0275(context.Background(), archive, dest, "", "", "", false, fixtureModpackOptions0275(server))
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "complete" || len(report.Imported) != 2 || len(report.Skipped) != 1 || report.PlanSHA256 == "" {
		t.Fatalf("incomplete report: %+v", report)
	}
	read := func(p string) []byte {
		b, e := os.ReadFile(filepath.Join(dest, p))
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	if !bytes.Equal(read("mods/a.jar"), mod) || string(read("config/feature.cfg")) != "client" {
		t.Fatal("download or layered overrides failed")
	}
	if _, e := os.Stat(filepath.Join(dest, "config/server.cfg")); !os.IsNotExist(e) {
		t.Fatal("server-only override should not be installed")
	}
	plan, e := readFactoryPlan0271(dest)
	if e != nil {
		t.Fatal(e)
	}
	if e = verifyFactoryPlan0271(dest, plan); e != nil {
		t.Fatal(e)
	}
	if plan.ReproducibilitySHA256 != report.PlanSHA256 {
		t.Fatal("reported identity differs from locked result")
	}
	if e = os.WriteFile(filepath.Join(dest, "mods/a.jar"), []byte("tampered"), 0644); e != nil {
		t.Fatal(e)
	}
	if e = verifyFactoryPlan0271(dest, plan); e == nil {
		t.Fatal("corrupted mod was accepted")
	}
}
func TestModpack0275CurseForgeResolvedDownloadURL(t *testing.T) {
	mod := []byte("curseforge-fixture-jar")
	s := fixtureModpackServer0275(t, mod)
	defer s.Close()
	idx := map[string]any{"manifestVersion": 1, "manifestType": "minecraftModpack", "name": "Curse Test", "version": "1.0", "minecraft": map[string]any{"version": "fixture-1", "modLoaders": []any{}}, "files": []any{map[string]any{"projectID": 101, "fileID": 202, "required": true}}, "overrides": "overrides"}
	raw, _ := json.Marshal(idx)
	archive := packFixtureZip0275(t, map[string][]byte{"manifest.json": raw, "overrides/config/cfg.json": []byte("{}")})
	dest := filepath.Join(t.TempDir(), "client")
	report, err := importModpack0275(context.Background(), archive, dest, "", s.URL, "test-api-key", false, fixtureModpackOptions0275(s))
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "complete" || len(report.Imported) != 2 {
		t.Fatalf("bad report: %+v", report)
	}
	b, err := os.ReadFile(filepath.Join(dest, "mods/cfmod.jar"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, mod) {
		t.Fatal("CurseForge downloaded wrong bytes")
	}
	p, err := readFactoryPlan0271(dest)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyFactoryPlan0271(dest, p); err != nil {
		t.Fatal(err)
	}
}
func TestModpack0275MissingOrWrongChecksumNeverPublishes(t *testing.T) {
	mod := []byte("checksum-mod")
	h512 := sha512.Sum512([]byte("other"))
	s := fixtureModpackServer0275(t, mod)
	defer s.Close()
	idx := map[string]any{"formatVersion": 1, "game": "minecraft", "versionId": "1.0", "name": "Bad SHA", "dependencies": map[string]string{"minecraft": "fixture-1"}, "files": []any{map[string]any{"path": "mods/mod.jar", "hashes": map[string]string{"sha1": sha1hex(mod), "sha512": hex.EncodeToString(h512[:])}, "downloads": []string{s.URL + "/mod.jar"}, "fileSize": len(mod)}}}
	raw, _ := json.Marshal(idx)
	archive := packFixtureZip0275(t, map[string][]byte{"modrinth.index.json": raw})
	dest := filepath.Join(t.TempDir(), "client")
	report, err := importModpack0275(context.Background(), archive, dest, "", "", "", false, fixtureModpackOptions0275(s))
	if err == nil || report.Status != "blocked" || len(report.Missing) != 1 {
		t.Fatalf("checksum mismatch must block: %+v %v", report, err)
	}
	if _, err = os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("partially imported client was published")
	}
}
func TestModpack0275RejectsUnsafePaths(t *testing.T) {
	for _, bad := range []string{"../escape", "overrides/../../escape", "overrides/CON.txt", "overrides/libraries/../../evil", "overrides\\config\\win", "overrides/.launcher/install-plan.json"} {
		t.Run(strings.ReplaceAll(bad, "/", "_"), func(t *testing.T) {
			index := []byte(`{"formatVersion":1,"game":"minecraft","versionId":"a","name":"a","dependencies":{"minecraft":"1.20.1"},"files":[]}`)
			name := bad
			if strings.HasPrefix(name, "overrides/") && strings.HasSuffix(name, ".launcher/install-plan.json") {
				name = "overrides/.launcher/install-plan.json"
			}
			archive := packFixtureZip0275(t, map[string][]byte{"modrinth.index.json": index, name: []byte("bad")})
			spec, z, e := parseModpack0275(archive, false)
			if z != nil {
				z.Close()
			}
			if e == nil {
				t.Fatalf("unsafe path accepted: %+v", spec)
			}
		})
	}
}
func TestModpack0275CurseMissingAPIKey(t *testing.T) {
	archive := packFixtureZip0275(t, map[string][]byte{"manifest.json": []byte(`{"manifestType":"minecraftModpack","manifestVersion":1,"name":"Pack","minecraft":{"version":"1.20.1"},"files":[{"projectID":42,"fileID":77,"required":true}]}`)})
	dest := filepath.Join(t.TempDir(), "client")
	r, e := importModpack0275(context.Background(), archive, dest, "", "", "", false, factoryBuildOptions0271{})
	if e == nil || r.Status != "blocked" || len(r.Missing) != 1 {
		t.Fatalf("missing file must block: %v %+v", e, r)
	}
	if _, e = os.Stat(dest); !os.IsNotExist(e) {
		t.Fatal("created destination despite missing key")
	}
}

func TestModpack0275ManualVerifiedFallback(t *testing.T) {
	mod := []byte("manual-modrinth-binary")
	hash := sha512.Sum512(mod)
	s := fixtureModpackServer0275(t, mod)
	defer s.Close()
	idx := map[string]any{"formatVersion": 1, "game": "minecraft", "versionId": "v1", "name": "Manual Pack", "dependencies": map[string]string{"minecraft": "fixture-1"}, "files": []any{map[string]any{"path": "mods/fallback.jar", "hashes": map[string]string{"sha1": sha1hex(mod), "sha512": hex.EncodeToString(hash[:])}, "downloads": []string{s.URL + "/not-found"}, "fileSize": len(mod)}}}
	raw, _ := json.Marshal(idx)
	archive := packFixtureZip0275(t, map[string][]byte{"modrinth.index.json": raw})
	manual := t.TempDir()
	if err := os.WriteFile(filepath.Join(manual, "fallback.jar"), mod, 0600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "client")
	report, err := importModpack0275(context.Background(), archive, dst, manual, "", "", false, fixtureModpackOptions0275(s))
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "complete" || len(report.Missing) > 0 {
		t.Fatalf("failed manual verified fallback: %+v", report)
	}
	p, err := readFactoryPlan0271(dst)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyFactoryPlan0271(dst, p); err != nil {
		t.Fatal(err)
	}
}

func TestModpack0275InspectDoesNotTouchNetwork(t *testing.T) {
	idx := []byte(`{"formatVersion":1,"game":"minecraft","versionId":"v","name":"Inspect Pack","dependencies":{"minecraft":"1.21.1","neoforge":"21.1.100"},"files":[]}`)
	archive := packFixtureZip0275(t, map[string][]byte{"modrinth.index.json": idx})
	dest := filepath.Join(t.TempDir(), "inspection.json")
	if err := handleModpack0275([]string{"inspect-modpack", "--file", archive, "--output", dest}); err != nil {
		t.Fatal(err)
	}
	var got modpackReport0275
	b, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Loader != "neoforge" || got.LoaderVersion != "21.1.100" || got.Status != "inspected" {
		t.Fatalf("incorrect inspect result: %+v", got)
	}
}

func TestModpack0275CommandIntegrationAndExplicitMissing(t *testing.T) {
	payload := []byte("works")
	hash := sha512.Sum512(payload)
	s := fixtureModpackServer0275(t, payload)
	defer s.Close()
	idx := map[string]any{"formatVersion": 1, "game": "minecraft", "name": "No Download", "versionId": "v2", "dependencies": map[string]string{"minecraft": "fixture-1"}, "files": []any{map[string]any{"path": "mods/no-url.jar", "hashes": map[string]string{"sha1": sha1hex(payload), "sha512": hex.EncodeToString(hash[:])}, "downloads": []string{}, "fileSize": len(payload)}}}
	raw, _ := json.Marshal(idx)
	archive := packFixtureZip0275(t, map[string][]byte{"modrinth.index.json": raw})
	root := t.TempDir()
	client := filepath.Join(root, "no-install")
	reportFile := filepath.Join(root, "missing.json")
	e := handleRuntimeFactory0271([]string{"import-modpack", "--file", archive, "--client-dir", client, "--report", reportFile, "--version-manifest", s.URL + "/manifest.json"})
	if e == nil {
		t.Fatal("must refuse missing download URL")
	}
	rawReport, err := os.ReadFile(reportFile)
	if err != nil {
		t.Fatal(err)
	}
	var report modpackReport0275
	if err = json.Unmarshal(rawReport, &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "blocked" || len(report.Missing) != 1 || report.Missing[0].Path != "mods/no-url.jar" {
		t.Fatalf("missing report invalid: %+v", report)
	}
	if _, e = os.Stat(client); !os.IsNotExist(e) {
		t.Fatal("published incomplete client")
	}
	// Verified manual fallback through the exact same CLI route.
	manual := filepath.Join(root, "manual")
	if err = os.MkdirAll(manual, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(manual, "no-url.jar"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	success := filepath.Join(root, "success.json")
	e = handleRuntimeFactory0271([]string{"import-modpack", "--file", archive, "--client-dir", client, "--manual-dir", manual, "--output", success, "--version-manifest", s.URL + "/manifest.json", "--asset-base-url", s.URL + "/assets"})
	if e != nil {
		t.Fatal(e)
	}
	rawReport, err = os.ReadFile(success)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(rawReport, &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "complete" || report.PlanSHA256 == "" {
		t.Fatalf("CLI import failed: %+v", report)
	}
	plan, err := readFactoryPlan0271(client)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyFactoryPlan0271(client, plan); err != nil {
		t.Fatal(err)
	}
}
