package httpapi

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func signedRuntimeContract0192(t *testing.T, serverID, platform string, identity testBridgeNodeIdentity0142, startedAt time.Time, pid int64, capabilities []string) bridgeRuntimeIdentityV3Contract0192 {
	t.Helper()
	startedAt = startedAt.UTC().Truncate(time.Millisecond)
	r := bridgeRuntimeIdentityV3Contract0192{
		StartedAt:           startedAt.Format(time.RFC3339Nano),
		StartedAtUnixMillis: startedAt.UnixMilli(),
		UptimeSeconds:       65,
		ProcessID:           pid,
		Hostname:            "mc-node-01.example.internal",
		NodeName:            "mc-paper-primary",
		MinecraftVersion:    "1.21.1",
		JavaVersion:         "21.0.8",
		JavaVendor:          "Eclipse Adoptium",
		JavaVMName:          "OpenJDK 64-Bit Server VM",
		Platform:            platform,
		LoaderName:          "Paper",
		LoaderVersion:       "1.21.1-131",
		ServerBrand:         "Paper 1.21.1-131",
		Capabilities:        append([]string(nil), capabilities...),
		NodeKeyFingerprint:  identity.Fingerprint,
	}
	normalized := normalizeBridgeFeatures0191(r.Capabilities)
	r.RuntimeID = bridgeRuntimeID0192(serverID, identity.Fingerprint, r.StartedAtUnixMillis, pid, r.Hostname)
	canonical := bridgeRuntimeCanonical0192(serverID, r, normalized)
	r.IdentitySignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(identity.PrivateKey, []byte(canonical)))
	return r
}

func TestServerBridgeRuntimeIdentity0192VerifiesNodeBoundProcessIdentity(t *testing.T) {
	identity := newTestBridgeNodeIdentity0142(t)
	server := bridgeServerRecord{
		ID: "paper-runtime-0192", Kind: "paper", Status: "active",
		KeyFingerprint: identity.Fingerprint, PublicKey: identity.Encoded, IdentityEpoch: 4,
	}
	started := time.Now().UTC().Add(-65 * time.Second)
	runtimeContract := signedRuntimeContract0192(t, server.ID, "paper", identity, started, 48120, []string{
		"runtime.ed25519-attestation", "plugin.bukkit-api", "runtime.discovery",
	})
	req := bridgePluginHeartbeatRequest940{ServerType: "paper", Runtime: &runtimeContract}

	verified, err := validateAndVerifyBridgeRuntime0192(server, req, time.Now().UTC())
	if err != nil {
		t.Fatalf("valid runtime identity rejected: %v", err)
	}
	if verified.RuntimeID != runtimeContract.RuntimeID || verified.NodeKeyFingerprint != identity.Fingerprint || verified.ProcessID != 48120 {
		t.Fatalf("verified runtime mismatch: %+v", verified)
	}
	if got := strings.Join(verified.Capabilities, ","); got != "plugin.bukkit-api,runtime.discovery,runtime.ed25519-attestation" {
		t.Fatalf("capabilities were not canonicalized: %s", got)
	}

	// Process facts are part of both the deterministic runtime id and Ed25519
	// attestation. Changing PID without minting a new runtime identity must fail.
	tampered := runtimeContract
	tampered.ProcessID++
	req.Runtime = &tampered
	if _, err := validateAndVerifyBridgeRuntime0192(server, req, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "runtime_id_binding_invalid") {
		t.Fatalf("tampered process identity accepted: %v", err)
	}

	// Discovery facts are covered by the Ed25519 runtime signature.
	tampered = runtimeContract
	tampered.MinecraftVersion = "1.21.2"
	req.Runtime = &tampered
	if _, err := validateAndVerifyBridgeRuntime0192(server, req, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "runtime_signature_invalid") {
		t.Fatalf("tampered discovery metadata accepted: %v", err)
	}
}

func TestServerBridgeRuntimeIdentity0192DetectsReplacementAndRestart(t *testing.T) {
	store := &serverBridgeStore{servers: map[string]bridgeServerRecord{
		"paper-runtime-0192": {
			ID: "paper-runtime-0192", Kind: "paper", Status: "active", KeyFingerprint: strings.Repeat("a", 64),
		},
	}}
	base := model.ServerBridgeRuntimeIdentity{
		RuntimeID: strings.Repeat("1", 64), IdentityDigest: strings.Repeat("b", 64), NodeKeyFingerprint: strings.Repeat("a", 64),
		StartedAt: time.Now().UTC().Add(-time.Minute), UptimeSeconds: 60, ProcessID: 1001,
		Hostname: "node-a", NodeName: "paper-a", MinecraftVersion: "1.21.1", JavaVersion: "21.0.8",
		Platform: "paper", LoaderName: "Paper", LoaderVersion: "1.21.1-131", ServerBrand: "Paper",
		Capabilities: []string{"runtime.discovery"},
	}

	first, err := store.markRuntimeHeartbeat0192("paper-runtime-0192", "paper", "0.19.2", 3, base)
	if err != nil || first.Transition != "started" || first.RuntimeEpoch != 1 || first.ReplacementDetected {
		t.Fatalf("first runtime transition invalid: %+v err=%v", first, err)
	}
	same, err := store.markRuntimeHeartbeat0192("paper-runtime-0192", "paper", "0.19.2", 3, base)
	if err != nil || same.Transition != "unchanged" || same.RuntimeEpoch != 1 {
		t.Fatalf("same runtime was not kept stable: %+v err=%v", same, err)
	}

	replacement := base
	replacement.RuntimeID = strings.Repeat("2", 64)
	replacement.IdentityDigest = strings.Repeat("c", 64)
	replacement.StartedAt = base.StartedAt.Add(30 * time.Second)
	replacement.ProcessID = 1002
	repl, err := store.markRuntimeHeartbeat0192("paper-runtime-0192", "paper", "0.19.2", 3, replacement)
	if err != nil || repl.Transition != "replacement" || !repl.ReplacementDetected || repl.PreviousRuntimeID != base.RuntimeID || repl.RuntimeEpoch != 2 {
		t.Fatalf("overlapping replacement was not detected: %+v err=%v", repl, err)
	}

	// A late heartbeat from the replaced JVM must never flip the active runtime
	// back to an older process generation.
	if _, err := store.markRuntimeHeartbeat0192("paper-runtime-0192", "paper", "0.19.2", 3, base); err == nil || !strings.Contains(err.Error(), "older than active runtime") {
		t.Fatalf("superseded runtime reclaimed active state: %v", err)
	}

	store.mu.Lock()
	old := store.servers["paper-runtime-0192"]
	old.RuntimeLastSeenAt = time.Now().UTC().Add(-2*time.Minute - time.Second)
	store.servers["paper-runtime-0192"] = old
	store.mu.Unlock()

	restart := base
	restart.RuntimeID = strings.Repeat("3", 64)
	restart.IdentityDigest = strings.Repeat("d", 64)
	restart.StartedAt = replacement.StartedAt.Add(30 * time.Second)
	restart.ProcessID = 1003
	next, err := store.markRuntimeHeartbeat0192("paper-runtime-0192", "paper", "0.19.2", 3, restart)
	if err != nil || next.Transition != "restart" || next.ReplacementDetected || next.PreviousRuntimeID != replacement.RuntimeID || next.RuntimeEpoch != 3 {
		t.Fatalf("restart transition invalid: %+v err=%v", next, err)
	}
}

func TestServerBridgeRuntimeIdentity0192FeaturePairIsAtomic(t *testing.T) {
	if enabled, reason := bridgeRuntimeFeatureMode0192([]string{serverBridgeFeatureRuntimeDiscovery}); enabled || reason != "serverbridge_runtime_feature_pair_incomplete" {
		t.Fatalf("partial runtime feature pair accepted: enabled=%v reason=%s", enabled, reason)
	}
	if enabled, reason := bridgeRuntimeFeatureMode0192([]string{serverBridgeFeatureRuntimeDiscovery, serverBridgeFeatureRuntimeIdentity}); !enabled || reason != "" {
		t.Fatalf("complete runtime feature pair rejected: enabled=%v reason=%s", enabled, reason)
	}
}
