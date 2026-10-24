package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientFactoryGA0280SignedJoinTampering(t *testing.T) {
	root := t.TempDir()
	private, pub := filepath.Join(root, "private.key"), filepath.Join(root, "public.key")
	if err := factoryCertKeygen02712(private, pub); err != nil {
		t.Fatal(err)
	}
	commit := strings.Repeat("a", 40)
	evidence := filepath.Join(root, "matching-server.json")
	content := `{"status":"passed","minecraftVersion":"1.21.1","clientVersion":"1.21.1","serverVersion":"1.21.1","serverHost":"127.0.0.1","clientJoinedServer":true,"serverVersionMatched":true,"actualClient":true,"serverProcessAlive":true}`
	if err := os.WriteFile(evidence, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	signed := filepath.Join(root, "join-attestation.json")
	if _, err := factorySignJoin0280(evidence, private, "0.28.0", commit, signed); err != nil {
		t.Fatal(err)
	}
	if _, _, err := factoryVerifyJoin0280(evidence, signed, pub, "0.28.0", commit); err != nil {
		t.Fatal(err)
	}
	if _, _, err := factoryVerifyJoin0280(evidence, signed, pub, "0.28.0", strings.Repeat("b", 40)); err == nil {
		t.Fatal("accepted different release commit")
	}
	if _, _, err := factoryVerifyJoin0280(evidence, signed, pub, "0.27.12", commit); err == nil {
		t.Fatal("accepted different product version")
	}
	newPrivate, newPub := filepath.Join(root, "other.key"), filepath.Join(root, "other.pub")
	if err := factoryCertKeygen02712(newPrivate, newPub); err != nil {
		t.Fatal(err)
	}
	if _, _, err := factoryVerifyJoin0280(evidence, signed, newPub, "0.28.0", commit); err == nil {
		t.Fatal("accepted different trust root")
	}
	if err := os.WriteFile(evidence, []byte(content+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := factoryVerifyJoin0280(evidence, signed, pub, "0.28.0", commit); err == nil {
		t.Fatal("accepted modified evidence")
	}
}
func TestClientFactoryGA0280IncompleteEvidenceFailsClosed(t *testing.T) {
	root := t.TempDir()
	evidence := filepath.Join(root, "join.json")
	for _, bad := range []string{
		`{"status":"passed","minecraftVersion":"1.21.1","clientVersion":"1.21.1","serverVersion":"1.21.1","serverHost":"127.0.0.1","clientJoinedServer":false,"serverVersionMatched":true,"actualClient":true,"serverProcessAlive":true}`,
		`{"status":"passed","minecraftVersion":"1.21.1","clientVersion":"1.21.1","serverVersion":"1.20.1","serverHost":"127.0.0.1","clientJoinedServer":true,"serverVersionMatched":true,"actualClient":true,"serverProcessAlive":true}`,
		`{"status":"passed","minecraftVersion":"1.21.1","clientVersion":"1.21.1","serverVersion":"1.21.1","serverHost":"evil.com","clientJoinedServer":true,"serverVersionMatched":true,"actualClient":true,"serverProcessAlive":true}`,
	} {
		if err := os.WriteFile(evidence, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := factoryReadJoinEvidence0280(evidence); err == nil {
			t.Fatalf("accepted incomplete server join: %s", bad)
		}
	}
	if _, err := factoryVerifyGA0280("", "", "", "", "", "0.28.0", strings.Repeat("a", 40)); err == nil {
		t.Fatal("certified GA without runtime matrix and trusted join proof")
	}
}
