package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOfflineGuardRevokeAndRollback05011(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "private.hex")
	pub := filepath.Join(dir, "public.hex")
	if err := keygen(priv, pub); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "source.json")
	raw := []byte(`{"schemaVersion":"launcher.guard-compatibility.v1","projectId":"project","minecraft":"1.20.1","loader":"fabric","epoch":1,"issuedAt":1750000000,"expiresAt":1750003600,"artifacts":[],"transformations":[],"revokedDigests":[],"revokedTransformations":[]}`)
	if err := os.WriteFile(source, raw, 0600); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(dir, "first.json")
	if err := sign(source, priv, first); err != nil {
		t.Fatal(err)
	}
	revoked := filepath.Join(dir, "revoked.json")
	digest := strings.Repeat("a", 64)
	if err := operatorRevise05011("revoke", first, "", priv, revoked, digest, "hook.one", time.Now()); err != nil {
		t.Fatal(err)
	}
	key, _ := operatorKey05011(priv)
	newP, err := operatorParse05011(revoked, key)
	if err != nil {
		t.Fatal(err)
	}
	if newP.Epoch != 2 || len(newP.RevokedDigests) != 1 || len(newP.RevokedTransformations) != 1 {
		t.Fatalf("revoke lost fields: %+v", newP)
	}
	restored := filepath.Join(dir, "restored.json")
	if err := operatorRevise05011("rollback", revoked, first, priv, restored, "", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	restoredP, err := operatorParse05011(restored, key)
	if err != nil {
		t.Fatal(err)
	}
	if restoredP.Epoch != 3 || len(restoredP.RevokedDigests) != 1 || len(restoredP.RevokedTransformations) != 1 {
		t.Fatalf("rollback erased revocations %+v", restoredP)
	}
	if err := operatorRevise05011("rollback", revoked, revoked, priv, filepath.Join(dir, "invalid.json"), "", "", time.Now()); err == nil {
		t.Fatal("same-epoch rollback allowed")
	}
	if err := operatorRevise05011("revoke", revoked, "", priv, filepath.Join(dir, "invalid2.json"), "bad", "", time.Now()); err == nil {
		t.Fatal("bad hash revoked")
	}
	// Формируется допустимый подписанный конверт, который разбирается как подписанный объект JSON.
	var env signedPolicy05011
	data, _ := os.ReadFile(restored)
	if err := json.Unmarshal(data, &env); err != nil || env.Signature == "" {
		t.Fatal("bad signed output")
	}
}
