package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func createPublicMatrixFixture0159(t *testing.T, dir, ver string) DeliveryManifest {
	t.Helper()
	var names []string
	for _, arch := range []string{"x64", "arm64"} {
		w := expectedWindowsSignedArtifactsForVersion0157(ver, arch)
		wpkg, _ := expectedWindowsPackage0152(ver, arch)
		names = append(names, w["cli"], w["desktop-launcher"], w["guard"], w["runtime"], wpkg, managedJREArchiveName0155(ver, "windows", arch))

		l := expectedLinuxArtifacts0153(arch)
		lpkg, _ := expectedLinuxPackage0153(ver, arch)
		names = append(names, l["cli"], l["api"], l["desktop-launcher"], l["guard"], l["runtime"], lpkg, managedJREArchiveName0155(ver, "linux", arch))

		m := expectedMacOSArtifacts0154(arch)
		mpkg, _ := expectedMacOSPackage0154(ver, arch)
		names = append(names, m["cli"], m["desktop-launcher"], m["guard"], m["runtime"], mpkg, managedJREArchiveName0155(ver, "macos", arch))
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture:"+name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := buildDeliveryManifest0151(dir, ver)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeJSONFile(filepath.Join(dir, deliveryManifestFile0151), manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func TestPublicProductionDeliveryMatrix0159CoversSixTargets(t *testing.T) {
	dir := t.TempDir()
	ver := "0.15.9"
	manifest := createPublicMatrixFixture0159(t, dir, ver)
	matrix, err := buildPublicProductionDeliveryMatrix0159(dir, ver, "https://downloads.example.test/neverlauncher/v0.15.9", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(matrix.Targets) != 6 {
		t.Fatalf("targets=%d", len(matrix.Targets))
	}
	if len(matrix.Assets) != len(manifest.Artifacts) {
		t.Fatalf("assets=%d delivery=%d", len(matrix.Assets), len(manifest.Artifacts))
	}
	for _, target := range matrix.Targets {
		if target.CLI == "" || target.Desktop == "" || target.Guard == "" || target.Runtime == "" || target.Package == "" || target.ManagedJRE == "" {
			t.Fatalf("incomplete target: %+v", target)
		}
		if target.Platform == "linux" && target.API == "" {
			t.Fatalf("linux target missing API: %+v", target)
		}
	}
	matrix.Assets[0].URL = "https://evil.example/replace"
	if err := validatePublicProductionDeliveryMatrix0159(dir, matrix, ver, false); err == nil {
		t.Fatal("tampered asset URL must fail")
	}
}

func TestPublicProductionDeliveryMatrix0159RejectsMissingRuntime(t *testing.T) {
	dir := t.TempDir()
	ver := "0.15.9"
	createPublicMatrixFixture0159(t, dir, ver)
	if err := os.Remove(filepath.Join(dir, "neverruntime-windows-arm64.exe")); err != nil {
		t.Fatal(err)
	}
	if err := writeDeliveryManifest0151(dir, ver); err != nil {
		t.Fatal(err)
	}
	if _, err := buildPublicProductionDeliveryMatrix0159(dir, ver, "https://downloads.example.test/v0.15.9", false); err == nil || !strings.Contains(err.Error(), "neverruntime-windows-arm64.exe") {
		t.Fatalf("expected missing runtime failure, got %v", err)
	}
}

func TestFetchPublicMatrix0159LoopbackHTTP(t *testing.T) {
	dir := t.TempDir()
	ver := "0.15.9"
	createPublicMatrixFixture0159(t, dir, ver)
	var server *httptest.Server
	server = httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer server.Close()
	matrix, err := buildPublicProductionDeliveryMatrix0159(dir, ver, server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeJSONFile(filepath.Join(dir, publicProductionDeliveryMatrixFile0159), matrix); err != nil {
		t.Fatal(err)
	}
	downloadDir := t.TempDir()
	got, n, err := fetchPublicMatrix0159(context.Background(), server.URL+"/"+publicProductionDeliveryMatrixFile0159, downloadDir, true)
	if err != nil {
		t.Fatal(err)
	}
	if n <= 0 || got.BaseURL != server.URL || got.Version != ver {
		t.Fatalf("unexpected fetched matrix: bytes=%d matrix=%+v", n, got)
	}
}
