package fileauthlive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/fileauth"
	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector"
)

const firstUUID0426 = "37a144c1-263e-4e9b-820f-917640f95b2d"
const secondUUID0426 = "4eaa8b1a-3456-4de9-8d1d-123d6052489a"

func liveDatabase0426(uuid, name, password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return []byte(fmt.Sprintf(`{"%s":{"username":%q,"password":%q,"uuid":%q,"roles":["ADMIN"],"permissions":{"roles":["ADMIN"]},"accessToken":"MUST_NOT_LEAK"}}`, uuid, name, hex.EncodeToString(hash[:]), uuid))
}
func verifyLiveFixture0426(password, encoded string) bool {
	format, hash, ok := fileauth.DecodeCredential(encoded)
	if !ok {
		return false
	}
	if format == "phpass" {
		return fileauth.VerifyPHPass(password, hash)
	}
	return fileauth.VerifyDigest(password, format, hash)
}
func newLiveFixture0426(t *testing.T) (string, *LiveConnector) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "Database.json")
	if err := os.WriteFile(path, liveDatabase0426(firstUUID0426, "Alice_426", "OriginalSecret426"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := NewLiveConnector(context.Background(), LiveConfig{ID: "gravit-files", DatabasePath: path, PasswordFormat: "sha256-hex"}, verifyLiveFixture0426)
	if err != nil {
		t.Fatal(err)
	}
	return path, c
}
func login0426(c *LiveConnector, secret string) (authconnector.Authentication, error) {
	return c.AuthenticatePassword(context.Background(), authconnector.PasswordRequest{Identifier: "Alice_426", Secret: secret})
}
func TestLiveFileAuthReloadAndFailClosed0426(t *testing.T) {
	path, c := newLiveFixture0426(t)
	a, err := login0426(c, "OriginalSecret426")
	if err != nil || a.Identity.Subject != firstUUID0426 || a.Identity.Claims["minecraftUuid"] != firstUUID0426 {
		t.Fatalf("initial login %v %v", a, err)
	}
	if len(a.Identity.Roles) != 0 || len(a.Identity.Groups) != 0 {
		t.Fatal("Gravit roles imported")
	}
	if _, err := login0426(c, "wrong"); authconnector.CodeOf(err) != authconnector.ErrInvalidCredentials {
		t.Fatalf("wrong credential: %v", err)
	}
	if err := os.WriteFile(path+".next", liveDatabase0426(firstUUID0426, "Alice_426", "UpdatedSecret426"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".next", path); err != nil {
		t.Fatal(err)
	}
	if _, err := login0426(c, "OriginalSecret426"); authconnector.CodeOf(err) != authconnector.ErrInvalidCredentials {
		t.Fatalf("old password worked: %v", err)
	}
	if _, err := login0426(c, "UpdatedSecret426"); err != nil {
		t.Fatalf("new password rejected: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"broken":`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := login0426(c, "UpdatedSecret426"); authconnector.CodeOf(err) != authconnector.ErrUnavailable {
		t.Fatalf("corrupt file used cached accounts: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := login0426(c, "UpdatedSecret426"); authconnector.CodeOf(err) != authconnector.ErrUnavailable {
		t.Fatalf("missing file used cached accounts: %v", err)
	}
}
func TestLiveFileAuthSubjectDeletionAndSymlink0426(t *testing.T) {
	path, c := newLiveFixture0426(t)
	id, err := c.ResolveIdentity(context.Background(), authconnector.ResolveRequest{Subject: firstUUID0426})
	if err != nil || id.DisplayName != "Alice_426" {
		t.Fatalf("identity lookup %v %v", id, err)
	}
	profile, err := c.ResolveProfile(context.Background(), authconnector.ResolveRequest{Subject: firstUUID0426})
	if err != nil || profile.MinecraftUUID != firstUUID0426 {
		t.Fatalf("profile %v %v", profile, err)
	}
	if err := os.WriteFile(path, liveDatabase0426(secondUUID0426, "Bob_426", "another"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ResolveIdentity(context.Background(), authconnector.ResolveRequest{Subject: firstUUID0426}); authconnector.CodeOf(err) != authconnector.ErrIdentityNotFound {
		t.Fatalf("removed identity remained: %v", err)
	}
	if err := os.Rename(path, path+".real"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path+".real", path); err != nil {
		t.Fatal(err)
	}
	if _, err := login0426(c, "OriginalSecret426"); authconnector.CodeOf(err) != authconnector.ErrUnavailable {
		t.Fatalf("symlink source accepted: %v", err)
	}
}
func TestLiveFileAuthConfigValidation0426(t *testing.T) {
	path, _ := newLiveFixture0426(t)
	for _, bad := range []string{
		`[ {"id":"local","databasePath":"` + path + `","passwordFormat":"sha256-hex"} ]`,
		`[ {"id":"gravit-files","databasePath":"relative/Database.json","passwordFormat":"sha256-hex"} ]`,
		`[ {"id":"gravit-files","databasePath":"` + path + `","passwordFormat":"auto"} ]`,
		`[ {"id":"gravit-files","databasePath":"` + path + `","passwordFormat":"sha256-hex"}, {"id":"gravit-files","databasePath":"` + path + `","passwordFormat":"sha256-hex"} ]`,
		`[ {"id":"gravit-files","databasePath":"` + path + `","passwordFormat":"sha256-hex","unknown":true} ]`,
		`[] {}`, strings.Repeat("x", maxLiveConfigBytes+1),
	} {
		if _, err := LoadLiveConfigs(bad, ""); err == nil {
			t.Fatalf("invalid config accepted: %s", bad)
		}
	}
	if _, err := LoadLiveConfigs(`[]`, path); err == nil {
		t.Fatal("ambiguous source accepted")
	}
	cfgs, err := LoadLiveConfigs(`[ {"id":"gravit-files","databasePath":"`+path+`","passwordFormat":"sha256-hex","provisioning":{"mode":"jit"}} ]`, "")
	if err != nil || len(cfgs) != 1 || cfgs[0].Provisioning.Mode != "jit" {
		t.Fatalf("valid config %v %v", cfgs, err)
	}
}
func TestLiveFileAuthConcurrentSnapshotReload0426(t *testing.T) {
	path, c := newLiveFixture0426(t)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 15; j++ {
				_, _ = login0426(c, "OriginalSecret426")
			}
		}()
	}
	if err := os.WriteFile(path+".tmp", liveDatabase0426(firstUUID0426, "Alice_426", "NewSecret426"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if _, err := login0426(c, "NewSecret426"); err != nil {
		t.Fatal(err)
	}
}

func TestLiveFileAuthSameMtimeAndLengthStillReloads0426(t *testing.T) {
	path, c := newLiveFixture0426(t)
	old, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	data := liveDatabase0426(firstUUID0426, "Alice_426", "ReplacedSecret426")
	if int64(len(data)) != old.Size() {
		t.Fatal("fixture should have same size")
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, old.ModTime(), old.ModTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := login0426(c, "OriginalSecret426"); authconnector.CodeOf(err) != authconnector.ErrInvalidCredentials {
		t.Fatalf("content replacement with same size and mtime escaped cache invalidation: %v", err)
	}
	if _, err := login0426(c, "ReplacedSecret426"); err != nil {
		t.Fatal(err)
	}
}

func TestLiveFileAuthPHPass0426(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Database.json")
	source := fmt.Sprintf(`{"%s":{"username":"WP_Player","uuid":"%s","password":"$P$712345678o0hL6WBuvF/R0TpeZunPm0"}}`, firstUUID0426, firstUUID0426)
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := NewLiveConnector(context.Background(), LiveConfig{ID: "wp-files", DatabasePath: path, PasswordFormat: "phpass"}, verifyLiveFixture0426)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.AuthenticatePassword(context.Background(), authconnector.PasswordRequest{Identifier: "WP_Player", Secret: "Known-WordPress-Password"}); err != nil {
		t.Fatalf("correct PHPass password rejected: %v", err)
	}
	if _, err := c.AuthenticatePassword(context.Background(), authconnector.PasswordRequest{Identifier: "WP_Player", Secret: "wrong"}); authconnector.CodeOf(err) != authconnector.ErrInvalidCredentials {
		t.Fatalf("wrong PHPass password accepted: %v", err)
	}
}

func TestLiveFileAuthChangeDuringPasswordVerification0426(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Database.json")
	if err := os.WriteFile(path, liveDatabase0426(firstUUID0426, "Alice_426", "OriginalSecret426"), 0600); err != nil {
		t.Fatal(err)
	}
	verifier := func(password, encoded string) bool {
		if err := os.WriteFile(path+".next", liveDatabase0426(firstUUID0426, "Alice_426", "RevokedSecret426"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".next", path); err != nil {
			t.Fatal(err)
		}
		return verifyLiveFixture0426(password, encoded)
	}
	c, err := NewLiveConnector(context.Background(), LiveConfig{ID: "gravit-files", DatabasePath: path, PasswordFormat: "sha256-hex"}, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := login0426(c, "OriginalSecret426"); authconnector.CodeOf(err) != authconnector.ErrUnavailable {
		t.Fatalf("stale hash authenticated during source rotation: %v", err)
	}
}
