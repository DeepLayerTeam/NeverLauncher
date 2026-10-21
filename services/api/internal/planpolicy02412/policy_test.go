package planpolicy02412

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignedPolicyAndAdversarialMutations02412(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	p := Policy{SchemaVersion: "1.0", Epoch: 9, IssuedAt: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), RequireContinuousGuard: true,
		AllowedPlans: []AllowedPlan{{ServerID: "server", ProjectID: "project", ProfileID: "profile", Channel: "stable", ReleaseSignature: strings.Repeat("a", 128), CatalogDigest: strings.Repeat("b", 64), PlanSHA256: strings.Repeat("c", 64)}}}
	bytes, _ := json.Marshal(p)
	signature := ed25519.Sign(priv, append([]byte(Domain), bytes...))
	env := Envelope{SchemaVersion: "1.0", Payload: base64.StdEncoding.EncodeToString(bytes), Signature: hex.EncodeToString(signature)}
	dir := t.TempDir()
	path := filepath.Join(dir, "signed.json")
	write := func(e Envelope) {
		t.Helper()
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("NEVERLAUNCHER_SERVERBRIDGE_PLAN_POLICY_FILE", path)
	t.Setenv("NEVERLAUNCHER_SERVERBRIDGE_PLAN_POLICY_PUBLIC_KEY", hex.EncodeToString(pub))
	t.Setenv("NEVERLAUNCHER_SERVERBRIDGE_REQUIRE_PLAN_POLICY", "1")
	write(env)
	got, err := Load(now)
	if err != nil {
		t.Fatal(err)
	}
	if !Required() || !Matches(got, "server", "project", "profile", "stable", strings.Repeat("a", 128), strings.Repeat("b", 64), strings.Repeat("c", 64)) {
		t.Fatal("valid signed plan denied")
	}
	if Matches(got, "server", "project", "profile", "stable", strings.Repeat("a", 128), strings.Repeat("b", 64), strings.Repeat("d", 64)) {
		t.Fatal("tampered plan allowed")
	}
	if Matches(got, "other", "project", "profile", "stable", strings.Repeat("a", 128), strings.Repeat("b", 64), strings.Repeat("c", 64)) {
		t.Fatal("wrong server allowed")
	}
	if _, err = Load(now.Add(2 * time.Hour)); err == nil {
		t.Fatal("expired policy accepted")
	}
	// Mutation of a valid signed payload cannot retain its signature.
	mod := p
	mod.AllowedPlans[0].PlanSHA256 = strings.Repeat("d", 64)
	v, _ := json.Marshal(mod)
	env.Payload = base64.StdEncoding.EncodeToString(v)
	write(env)
	if _, err = Load(now); err == nil {
		t.Fatal("tampered payload accepted")
	}
	env.Payload = base64.StdEncoding.EncodeToString(bytes)
	env.Signature = strings.Repeat("0", 128)
	write(env)
	if _, err = Load(now); err == nil {
		t.Fatal("wrong signature accepted")
	}
	write(Envelope{SchemaVersion: "1.0", Payload: base64.StdEncoding.EncodeToString(bytes), Signature: hex.EncodeToString(signature)})
	t.Setenv("NEVERLAUNCHER_SERVERBRIDGE_PLAN_POLICY_PUBLIC_KEY", strings.Repeat("f", 64))
	if _, err = Load(now); err == nil {
		t.Fatal("wrong pinned key accepted")
	}
}
