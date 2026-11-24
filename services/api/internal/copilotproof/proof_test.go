package copilotproof

import (
	"testing"
	"time"
)

func TestCopilotProof(t *testing.T) {
	now := time.Unix(1234567890, 0)
	b := Binding{"admin", "session", "package-publish", "project", "package", "copilot:00000000-0000-4000-8000-000000000000"}
	raw := []byte(`{"expectedHeadRevision":9007199254740993,"packageId":"package"}`)
	secret := "test-secret"
	ticket, ok := Issue(secret, b, raw, now)
	if !ok || !Verify(secret, b, raw, ticket, now) {
		t.Fatal("valid preview rejected")
	}
	if !Verify(secret, b, []byte(`{"packageId": "package", "expectedHeadRevision":9007199254740993}`), ticket, now) {
		t.Fatal("JSONB normalization failed")
	}
	for _, tc := range []struct {
		name   string
		change func(*Binding)
	}{{"user", func(x *Binding) { x.User = "another" }}, {"session", func(x *Binding) { x.Session = "another" }}, {"kind", func(x *Binding) { x.Kind = "channel-rollback" }}, {"project", func(x *Binding) { x.Project = "other" }}, {"resource", func(x *Binding) { x.Resource = "other" }}, {"key", func(x *Binding) { x.Key += "x" }}} {
		t.Run(tc.name, func(t *testing.T) {
			x := b
			tc.change(&x)
			if Verify(secret, x, raw, ticket, now) {
				t.Fatal("accepted changed binding")
			}
		})
	}
	for _, tc := range []struct {
		name, secret, ticket string
		raw                  []byte
		now                  time.Time
	}{{"expiry", secret, ticket, raw, now.Add(TTL)}, {"wrong secret", "another", ticket, raw, now}, {"changed head", secret, ticket, []byte(`{"expectedHeadRevision":9007199254740992,"packageId":"package"}`), now}, {"tampered", secret, ticket + "a", raw, now}, {"missing", secret, "", raw, now}, {"future", secret, ticket, raw, now.Add(-time.Second)}} {
		t.Run(tc.name, func(t *testing.T) {
			if Verify(tc.secret, b, tc.raw, tc.ticket, tc.now) {
				t.Fatal("accepted invalid proof")
			}
		})
	}
	b.Session = ""
	if _, ok := Issue(secret, b, raw, now); ok {
		t.Fatal("issued without session")
	}
}
