package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestSQLiteHTTPDevicesJobsExtensionsRestart0373(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := OpenSQLiteHTTPRepository0372(ctx, path, "https://launcher.test")
	if err != nil {
		t.Fatal(err)
	}
	account := model.User{ID: "owner-1", Email: "owner@example.test", RoleID: "owner", Status: "active", PasswordHash: "argon2id-hash-excluded-from-api"}
	if _, err := db.SaveUser(account); err != nil {
		t.Fatal(err)
	}
	secret := model.ExtensionSecret{ExtensionID: "example.extension", Scope: "global", Name: "token", Ciphertext: bytes.Repeat([]byte{0x91}, 32), Nonce: bytes.Repeat([]byte{0x42}, 12), KeyVersion: "v1", UpdatedBy: "owner-1"}
	if _, err := db.PutExtensionSecret(ctx, secret); err != nil {
		t.Fatal(err)
	}
	device := model.TrustedDevice{ID: "device-1", UserID: "user-1", Name: "Laptop", Status: "active", PublicKey: "public-1", KeyFingerprint: "fingerprint-1"}
	if _, err = db.SaveTrustedDevice(ctx, device); err != nil {
		t.Fatal(err)
	}
	payload := json.RawMessage(`{"action":"verify"}`)
	job := model.DurableJob{Kind: "package-publish", ActorType: "user", ActorID: "operator", Action: "release:publish", ProjectID: "project-1", ResourceType: "package", ResourceID: "package-1", IdempotencyKey: "retry-key", Payload: payload}
	stored, created, err := db.EnqueueDurableJob(ctx, job, time.Hour)
	if err != nil || !created {
		t.Fatalf("enqueue: created=%v err=%v", created, err)
	}
	if _, err := db.SaveExtensionTrustPolicy(ctx, model.ExtensionTrustPolicy{Mode: model.ExtensionTrustModeAudit}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = OpenSQLiteHTTPRepository0372(ctx, path, "https://launcher.test")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	accountRestored, err := db.GetUser("owner-1")
	if err != nil || accountRestored.PasswordHash != account.PasswordHash {
		t.Fatalf("lost password verifier: %v", err)
	}
	secretRestored, err := db.GetExtensionSecret(ctx, "example.extension", "global", "", "token")
	if err != nil || !bytes.Equal(secret.Ciphertext, secretRestored.Ciphertext) || !bytes.Equal(secret.Nonce, secretRestored.Nonce) {
		t.Fatalf("lost extension ciphertext: %v", err)
	}
	deviceRestored, err := db.GetTrustedDevice("user-1", "device-1")
	if err != nil || deviceRestored.PublicKey != "public-1" {
		t.Fatalf("lost device public key: %v", err)
	}
	found, err := db.GetDurableJob(ctx, stored.ID)
	if err != nil || found.IdempotencyKey != "retry-key" {
		t.Fatalf("lost job: %+v %v", found, err)
	}
	_, created, err = db.EnqueueDurableJob(ctx, job, time.Hour)
	if err != nil || created {
		t.Fatalf("job replay: created=%v err=%v", created, err)
	}
	policy, err := db.GetExtensionTrustPolicy(ctx)
	if err != nil || policy.Mode != model.ExtensionTrustModeAudit {
		t.Fatalf("lost extension policy: %+v %v", policy, err)
	}
	if _, err := db.RevokeTrustedDevice(ctx, "user-1", "device-1", "security-incident"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = OpenSQLiteHTTPRepository0372(ctx, path, "https://launcher.test")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	item, err := db.GetTrustedDevice("user-1", "device-1")
	if err != nil || item.Status != "revoked" {
		t.Fatalf("revocation lost: %+v %v", item, err)
	}
	// Invalid component names may not read/write arbitrary SQLite tables.
	if err := db.WriteRuntimeComponent0373(ctx, "../sessions", []byte("x")); err == nil {
		t.Fatal("unrestricted runtime component")
	}
	if _, _, err := db.ReadRuntimeComponent0373(ctx, "../sessions"); err == nil {
		t.Fatal("unrestricted component read")
	}
}
