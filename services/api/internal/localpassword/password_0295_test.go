package localpassword

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/fileauth"
)

func TestLocalPasswordUpgrade0295(t *testing.T) {
	sum := sha256.Sum256([]byte("known-password"))
	legacy, err := fileauth.EncodeCredential("sha256-hex", hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	if !Verify("known-password", legacy) || Verify("unknown", legacy) || !NeedsRehash(legacy) {
		t.Fatal("legacy password cannot be safely upgraded")
	}
	argon, err := Hash("known-password")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(argon, "$argon2id$") || !Verify("known-password", argon) || Verify("unknown", argon) || NeedsRehash(argon) {
		t.Fatal("Argon2id hash or verify broken")
	}
	if Verify("known-password", legacy+"garbage") || Verify("known-password", "$never-gravit$v2$sha256-hex$") {
		t.Fatal("unknown format accepted")
	}
}

func TestExistingLegacyNeverSHA0295(t *testing.T) {
	sum := sha256.Sum256([]byte("old-pw"))
	stored := "sha256:" + hex.EncodeToString(sum[:])
	if !Verify("old-pw", stored) || !NeedsRehash(stored) || Verify("bad", stored) {
		t.Fatal("old local digest compatibility broken")
	}
}
