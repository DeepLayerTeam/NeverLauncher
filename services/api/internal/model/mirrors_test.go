package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestManifestMirrorsRoundTrip0234(t *testing.T) {
	in := ManifestFile{Path: "libraries/shared.jar", URL: "https://cdn.example.test/shared.jar", Mirrors: []string{
		"https://mirror-a.example.test/shared.jar", "https://mirror-b.example.test/shared.jar",
	}}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"mirrors":[`) {
		t.Fatalf("fallback sources missing: %s", b)
	}
	var decoded ManifestFile
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Mirrors) != 2 || decoded.Mirrors[0] != in.Mirrors[0] || decoded.Mirrors[1] != in.Mirrors[1] {
		t.Fatalf("mirror order changed: %+v", decoded.Mirrors)
	}
	b, err = json.Marshal(ManifestFile{Path: "a.jar"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "mirrors") {
		t.Fatalf("legacy manifests must omit absent mirrors: %s", b)
	}
}
