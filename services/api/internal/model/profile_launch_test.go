package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestConfiguredProfile0382KeepsHistoricalDigest(t *testing.T) {
	old := ProfileSpec{ProjectID: "project", ID: "vanilla", Name: "Vanilla", Loader: "vanilla"}
	data := strings.Join([]string{old.ProjectID, old.ID, old.Name, old.Description, old.Loader, old.Preset, "false"}, "\x00")
	sum := sha256.Sum256([]byte(data))
	if got := ProfileDigest(old); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("historical profile digest changed: %s", got)
	}
	modern := old
	modern.MinecraftVersion = "1.21.1"
	modern.JavaMajor = 21
	if ProfileDigest(modern) == ProfileDigest(old) {
		t.Fatal("configured profile must use a new digest")
	}
	p, err := NormalizeProfileV2(Profile{ProjectID: modern.ProjectID, ID: modern.ID, Name: modern.Name, Loader: modern.Loader, MinecraftVersion: modern.MinecraftVersion, JavaMajor: modern.JavaMajor})
	if err != nil {
		t.Fatal(err)
	}
	p.Revision = 2
	snap := SnapshotProfile(p)
	if snap.Revision != 2 || snap.Spec.MinecraftVersion != modern.MinecraftVersion || snap.Spec.JavaMajor != 21 {
		t.Fatalf("incomplete revision snapshot: %+v", snap)
	}
	if err := ValidateProfileSnapshot(snap, p.ProjectID, p.ID); err != nil {
		t.Fatal(err)
	}
	clone, err := CreateFromSnapshot0225(snap, "project", "vanilla-copy", "Clone")
	if err != nil || clone.MinecraftVersion != "1.21.1" || clone.JavaMajor != 21 {
		t.Fatalf("clone lost launch defaults: %+v %v", clone, err)
	}
}
func TestProfileLaunchMismatch0382(t *testing.T) {
	profile := ProfileSpec{ProjectID: "project", ID: "fabric", Name: "Fabric", Loader: "fabric", MinecraftVersion: "1.21.1", LoaderVersion: "0.16.14", JavaMajor: 21}
	valid := MinecraftInfo{Version: "1.21.1", Loader: "fabric", LoaderVersion: "0.16.14"}
	if err := ValidateProfileLaunch0382(profile, valid, 21, true); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		game MinecraftInfo
		java int
	}{
		{MinecraftInfo{Version: "1.20.4", Loader: "fabric", LoaderVersion: "0.16.14"}, 21},
		{MinecraftInfo{Version: "1.21.1", Loader: "forge", LoaderVersion: "0.16.14"}, 21},
		{MinecraftInfo{Version: "1.21.1", Loader: "fabric", LoaderVersion: "0.15"}, 21},
		{valid, 17},
	} {
		if err := ValidateProfileLaunch0382(profile, tc.game, tc.java, true); err == nil {
			t.Fatalf("accepted invalid launch %+v Java %d", tc.game, tc.java)
		}
	}
	if _, err := NormalizeProfileV2(Profile{ProjectID: "project", ID: "fabric", Name: "Fabric", Loader: "fabric", MinecraftVersion: "1.21.1", JavaMajor: 21}); err == nil {
		t.Fatal("unversioned modded profile accepted")
	}
	if err := ValidateProfileLaunch0382(ProfileSpec{Loader: "vanilla"}, MinecraftInfo{Version: "1.8.9", Loader: "vanilla"}, 8, true); err != nil {
		t.Fatal(fmt.Sprint(err))
	}
}
