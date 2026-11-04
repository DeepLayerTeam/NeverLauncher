package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func metaEntry0272(loader, ver string, stable bool) loaderMetaEntry {
	group, artifact := "net.fabricmc", "fabric-loader"
	if loader == "quilt" {
		group, artifact = "org.quiltmc", "quilt-loader"
	}
	return loaderMetaEntry{Loader: loaderMetaVersion{Version: ver, Maven: group + ":" + artifact + ":" + ver, Stable: stable}}
}

func TestModernLoader0272SelectorsWithUnsortedUpstream(t *testing.T) {
	for _, tc := range []struct {
		loader, selector, want string
		versions               []loaderMetaEntry
	}{
		{"fabric", "latest-stable", "0.18.0", []loaderMetaEntry{metaEntry0272("fabric", "0.16.10", true), metaEntry0272("fabric", "0.19.0-beta.2", false), metaEntry0272("fabric", "0.18.0", true), metaEntry0272("fabric", "0.17.9", true)}},
		{"fabric", "latest", "0.19.0-beta.10", []loaderMetaEntry{metaEntry0272("fabric", "0.19.0-beta.2", false), metaEntry0272("fabric", "0.18.0", true), metaEntry0272("fabric", "0.19.0-beta.10", false)}},
		{"quilt", "recommended", "0.30.0", []loaderMetaEntry{metaEntry0272("quilt", "0.9.9", true), metaEntry0272("quilt", "0.30.0-rc.2", false), metaEntry0272("quilt", "0.30.0", true), metaEntry0272("quilt", "0.29.9", true)}},
		{"quilt", "latest", "0.31.0-beta.2", []loaderMetaEntry{metaEntry0272("quilt", "0.30.0", true), metaEntry0272("quilt", "0.31.0-beta.2", false)}},
		{"fabric", "0.17.9", "0.17.9", []loaderMetaEntry{metaEntry0272("fabric", "0.17.9", true), metaEntry0272("fabric", "0.18.0", true)}},
	} {
		t.Run(tc.loader+"-"+tc.selector, func(t *testing.T) {
			selected, err := selectModernMetaEntry0272(tc.loader, "1.21.1", tc.selector, tc.versions)
			if err != nil {
				t.Fatal(err)
			}
			if selected.Loader.Version != tc.want {
				t.Fatalf("selected %s want %s", selected.Loader.Version, tc.want)
			}
		})
	}
}

func TestModernLoader0272RejectsAmbiguousAndForgedMetadata(t *testing.T) {
	a := metaEntry0272("fabric", "0.18.0", true)
	forged := a
	forged.Loader.Maven = "net.fabricmc:fabric-loader:0.17.0"
	if _, err := selectModernMetaEntry0272("fabric", "1.21.1", "0.18.0", []loaderMetaEntry{forged}); err == nil {
		t.Fatal("mismatched artifact was accepted")
	}
	if _, err := selectModernMetaEntry0272("fabric", "1.21.1", "latest", []loaderMetaEntry{a, forged}); err == nil {
		t.Fatal("conflicting duplicate was accepted")
	}
	missing := metaEntry0272("fabric", "0.18.0", false)
	if _, err := selectModernMetaEntry0272("fabric", "1.21.1", "latest-stable", []loaderMetaEntry{missing}); err == nil {
		t.Fatal("prerelease was accepted by stable policy")
	}
	if _, err := selectModernMetaEntry0272("fabric", "1.21.1", "0.19.0", []loaderMetaEntry{a}); err == nil {
		t.Fatal("unavailable explicit loader was accepted")
	}
	unsafe := metaEntry0272("quilt", "0.30.0/../../bad", true)
	if _, err := selectModernMetaEntry0272("quilt", "1.21.1", "0.30.0/../../bad", []loaderMetaEntry{unsafe}); err == nil {
		t.Fatal("unsafe loader version accepted")
	}
}

func TestModernLoader0272EscapesSnapshotPathAndPinsSourceHash(t *testing.T) {
	minecraft := "1.21 Pre-Release 1"
	loader := "fabric"
	ver := "0.18.0"
	path := "/versions/loader/" + url.PathEscape(minecraft)
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		if gotPath != path {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode([]loaderMetaEntry{metaEntry0272(loader, "0.17.0", true), metaEntry0272(loader, ver, true)})
	}))
	defer server.Close()
	entry, source, checksum, err := resolveMetaLoaderVersionWithEvidence(context.Background(), server.Client(), loader, server.URL, minecraft, "latest-stable")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != path || source != server.URL+path || entry.Loader.Version != ver || len(checksum) != 64 {
		t.Fatalf("invalid modern adapter resolution %q %+v %q", gotPath, entry, checksum)
	}
}

func TestModernLoader0272ForgeNeoForgeUnsafeVersionRejected(t *testing.T) {
	for _, value := range []string{"52.0.1/../../secret", "21.1.5?download=http://evil.invalid", "../bad", "21.1.3#fragment", "21.1.1\\../bad", "21.1.3%2Fother"} {
		if err := validateForgeLikeVersionToken0272(value); err == nil {
			t.Errorf("unsafe artifact version accepted: %q", value)
		}
	}
	for _, value := range []string{"1.21.1-52.0.1", "21.1.105", "21.1.105-beta", "26.1.0.1"} {
		if err := validateForgeLikeVersionToken0272(value); err != nil {
			t.Errorf("valid artifact version rejected %q: %v", value, err)
		}
	}
	_, _, _, _, err := resolveForgeLikeVersionWithEvidence(context.Background(), nil, "forge", "1.21.1", "52.0.1/../../bad", "")
	if err == nil {
		t.Fatal("forge accepted unsafe explicit selector")
	}
	_, _, _, _, err = resolveForgeLikeVersionWithEvidence(context.Background(), nil, "neoforge", "1.21.1", "21.1.1?bad", "")
	if err == nil {
		t.Fatal("neoforge accepted unsafe explicit selector")
	}
}

func TestModernLoader0272DuplicateLibrarySourceIsRejectedBeforeJarDownload(t *testing.T) {
	jar := []byte("loader jar fixture")
	maven := "net.fabricmc:fabric-loader:0.18.0"
	rel, err := strictMavenPath(maven)
	if err != nil {
		t.Fatal(err)
	}
	var downloads int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sha1") {
			w.Write([]byte(sha1hex(jar)))
		} else {
			downloads++
			w.Write(jar)
		}
	}))
	defer server.Close()
	profile := loaderVersionProfile{Libraries: []MojangLibrary{
		{Name: maven, URL: server.URL + "/first"},
		{Name: maven, URL: server.URL + "/second"},
	}}
	_, err = materializeLoaderLibraries(context.Background(), server.Client(), t.TempDir(), &profile, 1, true)
	if err == nil || !strings.Contains(err.Error(), "конфликт") {
		t.Fatalf("source provenance conflict undetected for %s: %v", rel, err)
	}
	if downloads != 0 {
		t.Fatalf("jar downloaded before conflict check: %d", downloads)
	}
}

func TestModernLoader0272MinecraftSnapshotSelectsExactVersion(t *testing.T) {
	manifest := MojangVersionManifest{Latest: map[string]string{"snapshot": "26w42a", "release": "1.21.1"}}
	if got := resolveRequestedMinecraftVersion(manifest, "snapshot"); got != "26w42a" {
		t.Fatalf("snapshot selected %q", got)
	}
	if got := resolveRequestedMinecraftVersion(manifest, "release"); got != "1.21.1" {
		t.Fatalf("release alias selected %q", got)
	}
	if _, exact := exactMinecraftVersionForRecovery("release"); exact {
		t.Fatal("mutable release alias is treated as immutable recovery input")
	}
}
