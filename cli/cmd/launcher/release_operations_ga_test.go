package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOperationsGA0460ExactBytesAndIndependentKey(t *testing.T) {
	root := t.TempDir()
	bundle := filepath.Join(root, "bundle")
	if e := os.Mkdir(bundle, 0700); e != nil {
		t.Fatal(e)
	}
	opPub, opPriv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	releasePub, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	key := filepath.Join(root, "operator.pub")
	if e := os.WriteFile(key, []byte(hex.EncodeToString(opPub)), 0600); e != nil {
		t.Fatal(e)
	}
	t.Setenv("LAUNCHER_OPERATIONS_GA_TRUSTED_PUBLIC_KEY_FILE", key)
	ver := "0.46.0"
	commit := strings.Repeat("a", 40)
	hash := func(raw []byte) string { s := sha256.Sum256(raw); return hex.EncodeToString(s[:]) }
	targets := map[string]operationsGATarget0460{}
	for _, tar := range distributionTargets04511(ver) {
		raw := []byte(tar.target + "-signed-final-bytes")
		if e := os.WriteFile(filepath.Join(bundle, tar.packageFile), raw, 0600); e != nil {
			t.Fatal(e)
		}
		targets[tar.target] = operationsGATarget0460{Name: tar.packageFile, SHA256: hash(raw)}
	}
	hashes := map[string]string{}
	for _, stage := range []string{"install-standard", "upgrade-standard", "restore-standard", "failover-network-ha"} {
		hashes[stage] = hash([]byte(stage))
	}
	approval := operationsGAApproval0460{Schema: "launcher.operations-ga.0460.v1", Version: ver,
		SourceCommit: commit, IssuedAt: time.Now().UTC().Format(time.RFC3339Nano), Operator: "operator2",
		SourceMachine: strings.Repeat("b", 64), RestoreMachine: strings.Repeat("c", 64), StageReceipts: hashes,
		OpenApiV1Sha256: hash([]byte("api")), Targets: targets,
		Scope: "actual independent operational acceptance; canary RPO only; no assertion of physical host HA or unmeasured workload RPO"}
	apiBOM, _ := json.Marshal(map[string]any{"components": []map[string]string{{"sourceFile": "schemas/openapi.yaml", "sourceSha256": hash([]byte("api"))}}})
	if e := os.WriteFile(filepath.Join(bundle, releaseBOMFile03214), apiBOM, 0600); e != nil {
		t.Fatal(e)
	}
	makeEvidence := func(a operationsGAApproval0460) {
		t.Helper()
		raw, e := json.Marshal(a)
		if e != nil {
			t.Fatal(e)
		}
		raw = append(raw, '\n')
		if e := os.WriteFile(filepath.Join(bundle, operationsGAFile0460), raw, 0600); e != nil {
			t.Fatal(e)
		}
		sig := ed25519.Sign(opPriv, append([]byte(operationsGADomain0460), raw...))
		if e := os.WriteFile(filepath.Join(bundle, operationsGASig0460), []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0600); e != nil {
			t.Fatal(e)
		}
		required := []string{operationsGAFile0460, operationsGASig0460}
		files := []map[string]any{}
		for _, name := range required {
			b, _ := os.ReadFile(filepath.Join(bundle, name))
			files = append(files, map[string]any{"name": name, "required": true, "status": "present", "sha256": hash(b)})
		}
		manifest, _ := json.Marshal(map[string]any{"version": ver, "sourceCommit": commit, "requiredFiles": required, "artifacts": files})
		if e := os.WriteFile(filepath.Join(bundle, "RELEASE_MANIFEST.json"), manifest, 0600); e != nil {
			t.Fatal(e)
		}
	}
	makeEvidence(approval)
	if e := verifyOperationsGA0460(bundle, ver, releasePub); e != nil {
		t.Fatalf("Отклонено подписанное свидетельство для точных байтов: %v", e)
	}
	if e := verifyOperationsGA0460(bundle, ver, opPub); e == nil {
		t.Fatal("Оператор выступает подписантом выпуска")
	}
	t.Run("tampered package", func(t *testing.T) {
		tar := distributionTargets04511(ver)[0].packageFile
		p := filepath.Join(bundle, tar)
		os.WriteFile(p, []byte("replaced"), 0600)
		if verifyOperationsGA0460(bundle, ver, releasePub) == nil {
			t.Fatal("Принят непроверенный пакет")
		}
	})
	os.WriteFile(filepath.Join(bundle, distributionTargets04511(ver)[0].packageFile), []byte(distributionTargets04511(ver)[0].target+"-signed-final-bytes"), 0600)
	t.Run("modified attestation", func(t *testing.T) {
		p := filepath.Join(bundle, operationsGAFile0460)
		old, _ := os.ReadFile(p)
		os.WriteFile(p, append(old, ' '), 0600)
		if verifyOperationsGA0460(bundle, ver, releasePub) == nil {
			t.Fatal("Принята недействительная подпись")
		}
		os.WriteFile(p, old, 0600)
	})
	t.Run("wrong commit", func(t *testing.T) {
		a := approval
		a.SourceCommit = strings.Repeat("d", 40)
		makeEvidence(a)
		if verifyOperationsGA0460(bundle, ver, releasePub) == nil {
			t.Fatal("Принят неправильный коммит")
		}
	})
	t.Run("expired", func(t *testing.T) {
		a := approval
		a.IssuedAt = time.Now().Add(-15 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
		makeEvidence(a)
		if verifyOperationsGA0460(bundle, ver, releasePub) == nil {
			t.Fatal("Принята подписанная квитанция с истёкшим сроком действия")
		}
	})
	t.Run("api mismatch", func(t *testing.T) {
		a := approval
		a.OpenApiV1Sha256 = hash([]byte("changed api"))
		makeEvidence(a)
		if verifyOperationsGA0460(bundle, ver, releasePub) == nil {
			t.Fatal("Допущено несоответствие API фактической спецификации исходных компонентов")
		}
	})
	t.Run("missing key", func(t *testing.T) {
		t.Setenv("LAUNCHER_OPERATIONS_GA_TRUSTED_PUBLIC_KEY_FILE", "")
		if verifyOperationsGA0460(bundle, ver, releasePub) == nil {
			t.Fatal("Принято отсутствие корня доверия")
		}
	})
}
