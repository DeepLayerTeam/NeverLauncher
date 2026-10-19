package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientStateCASPreventsStaleUpdate0228(t *testing.T) {
	root := t.TempDir()
	before, err := clientStateSHA2560228(root)
	if err != nil || before != "absent" {
		t.Fatalf("empty state: %s %v", before, err)
	}
	dir := filepath.Join(root, ".neverlauncher")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "client-state.json"), []byte(`{"version":"1"}`), 0600); err != nil {
		t.Fatal(err)
	}
	after, err := clientStateSHA2560228(root)
	if err != nil || after == before {
		t.Fatalf("updated hash %q %v", after, err)
	}
	u, err := newTransactionalUpdater0156(root)
	if err != nil {
		t.Fatal(err)
	}
	_, err = u.apply(updaterRequest0156{Root: root, Namespace: "client-package", FromVersion: "", ToVersion: "2", ExpectedStateSHA256: before})
	if err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("expected stale-state conflict: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "client-state.json"))
	if err != nil || string(raw) != `{"version":"1"}` {
		t.Fatalf("state mutated: %s %v", raw, err)
	}
	_, err = u.apply(updaterRequest0156{Root: root, Namespace: "client-package", FromVersion: "1", ToVersion: "2", ExpectedStateSHA256: after})
	if err != nil {
		t.Fatalf("matching state should commit: %v", err)
	}
}

func TestClientStateActivationHappensAfterVerifiedFiles0228(t *testing.T) {
	root := t.TempDir()
	control := filepath.Join(root, ".neverlauncher")
	if err := os.MkdirAll(control, 0700); err != nil {
		t.Fatal(err)
	}
	pointer := filepath.Join(control, "client-state.json")
	if err := os.WriteFile(pointer, []byte(`{"version":"old"}`), 0600); err != nil {
		t.Fatal(err)
	}
	old, err := clientStateSHA2560228(root)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("new-managed-bytes")
	newPointer := []byte(`{"version":"new"}`)
	payloadSize, payloadSHA := updaterBytesMetadata0156(payload)
	stateSize, stateSHA := updaterBytesMetadata0156(newPointer)
	updater, err := newTransactionalUpdater0156(root)
	if err != nil {
		t.Fatal(err)
	}
	_, err = updater.apply(updaterRequest0156{
		Root: root, Namespace: "client-package", ExpectedStateSHA256: old,
		Files: []updaterFileSpec0156{
			{Path: "managed/data.bin", Data: payload, Size: payloadSize, SHA256: payloadSHA},
			{Path: ".neverlauncher/client-state.json", Data: newPointer, Size: stateSize, SHA256: stateSHA},
		},
		Verify: func() error {
			raw, readErr := os.ReadFile(pointer)
			if readErr != nil {
				return readErr
			}
			if string(raw) != `{"version":"old"}` {
				return fmt.Errorf("client active pointer switched before validation: %s", raw)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(pointer)
	if err != nil || string(raw) != string(newPointer) {
		t.Fatalf("activation failed: %s %v", raw, err)
	}
	raw, err = os.ReadFile(filepath.Join(root, "managed", "data.bin"))
	if err != nil || string(raw) != string(payload) {
		t.Fatalf("managed file absent: %s %v", raw, err)
	}
}
