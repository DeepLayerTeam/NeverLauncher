package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRemoteLocalInspectionPreservesUnknownOutcome0285(t *testing.T) {
	root := t.TempDir()
	_, err := remoteInit0284(root)
	if err != nil {
		t.Fatal(err)
	}
	key := "host-uncertain-0285-0001"
	dir := remoteDir0284(root)
	path := remoteReceiptFile0284(dir, key)
	receipt := remoteReceipt0284{
		SchemaVersion: "1.0", KeyHash: filepath.Base(path)[:64],
		Digest: "one-shot", Subject: "operator", Action: "stop", State: "indeterminate",
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := remotePersistReceipt0284(path, receipt); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "inspect.json")
	if err := remoteHandle0284([]string{"inspect", "--server-root", root, "--idempotency-key", key, "--output", output}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Receipt                remoteReceipt0284 `json:"receipt"`
		VerifiedExternalEffect bool              `json:"verifiedExternalEffect"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Receipt.State != "indeterminate" || result.VerifiedExternalEffect {
		t.Fatalf("unsafe proof or hidden uncertainty: %s", data)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(original, []byte(`"indeterminate"`)) {
		t.Fatal("inspection mutated receipt")
	}
	if err := remoteHandle0284([]string{"inspect", "--server-root", root, "--idempotency-key", "other-key-000000001"}); err == nil {
		t.Fatal("missing journal accepted")
	}
	if err := remoteHandle0284([]string{"inspect", "--server-root", root, "--idempotency-key", "bad"}); err == nil {
		t.Fatal("invalid key accepted")
	}
}
