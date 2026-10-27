package sqlitecore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/sqlitedurable"
)

func TestFullStatePackagesSignaturesCASRestartAndRevocation(t *testing.T) {
	r, path := openTest(t)
	ctx := context.Background()
	if _, e := r.SaveUser(ctx, model.User{ID: "owner", Email: "owner@test.example", RoleID: "owner", Status: "active"}, "bootstrap"); e != nil {
		t.Fatal(e)
	}
	data := []byte("signed extension package bytes; no external blob dependency")
	pkg, created, e := r.PutPackage(ctx, data, "owner")
	if e != nil || !created {
		t.Fatalf("put: %v %v", created, e)
	}
	p2, created, e := r.PutPackage(ctx, data, "owner")
	if e != nil || created || pkg.Digest != p2.Digest {
		t.Fatalf("dedup: %v %v", created, e)
	}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.RegisterExtensionPublisher(ctx, "publisher", hex.EncodeToString(pub), "owner"); e != nil {
		t.Fatal(e)
	}
	in := ExtensionPackage{ExtensionID: "org.example.test", Version: "1.0.0", Publisher: "publisher", Digest: pkg.Digest}
	in.SignatureHex = hex.EncodeToString(ed25519.Sign(priv, extensionSignatureMessage(in.ExtensionID, in.Version, in.Digest)))
	if _, e = r.PublishExtensionPackage(ctx, in, "owner"); e != nil {
		t.Fatal(e)
	}
	bad := in
	bad.Version = "1.0.1"
	if _, e = r.PublishExtensionPackage(ctx, bad, "owner"); !errors.Is(e, ErrAuthentication) {
		t.Fatalf("signature replay accepted: %v", e)
	}
	// A single CAS writer wins. Every generation preserves append-only provenance.
	inst := SQLiteExtensionInstall{ExtensionID: in.ExtensionID, Scope: "global", Version: in.Version, PackageDigest: pkg.Digest, State: "enabled", Actor: "owner"}
	installed, e := r.ApplyExtensionInstall326(ctx, inst, 0)
	if e != nil || installed.Generation != 1 {
		t.Fatalf("install: %+v %v", installed, e)
	}
	var success atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v := inst
			v.State = "disabled"
			_, err := r.ApplyExtensionInstall326(ctx, v, 1)
			if err == nil {
				success.Add(1)
			} else if !errors.Is(err, ErrConflict) {
				t.Errorf("CAS: %v", err)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatalf("CAS winners=%d", success.Load())
	}
	installed, e = r.GetExtensionInstall326(ctx, in.ExtensionID, "global", "")
	if e != nil || installed.Generation != 2 || installed.State != "disabled" {
		t.Fatalf("after CAS: %+v %v", installed, e)
	}
	inst.State = "enabled"
	installed, e = r.ApplyExtensionInstall326(ctx, inst, 2)
	if e != nil {
		t.Fatal(e)
	}
	state := SQLiteExtensionState{ExtensionID: in.ExtensionID, Scope: "global", Key: "settings", Value: `{"level":1}`}
	v, e := r.PutExtensionState326(ctx, state, 0, "owner")
	if e != nil || v.Generation != 1 {
		t.Fatalf("state: %v %+v", e, v)
	}
	if _, e = r.PutExtensionState326(ctx, state, 0, "owner"); !errors.Is(e, ErrConflict) {
		t.Fatalf("CAS stale state: %v", e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenExisting(ctx, sqlitedurable.Options{Path: path})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	raw, e := r.ReadPackage(ctx, pkg.Digest)
	if e != nil || string(raw) != string(data) {
		t.Fatalf("package lost: %v", e)
	}
	restored, e := r.GetExtensionState326(ctx, in.ExtensionID, "global", "", "settings")
	if e != nil || restored.Generation != 1 {
		t.Fatalf("state lost: %v %+v", e, restored)
	}
	if e = r.SetExtensionPublisherActive(ctx, "publisher", "owner", false); e != nil {
		t.Fatal(e)
	}
	installed, e = r.GetExtensionInstall326(ctx, in.ExtensionID, "global", "")
	if e != nil || installed.State != "disabled" || installed.Generation != 4 {
		t.Fatalf("publisher revoke must disable: %v %+v", e, installed)
	}
	if _, e = r.ApplyExtensionInstall326(ctx, inst, 4); !errors.Is(e, ErrAuthentication) {
		t.Fatalf("revoked publisher install accepted: %v", e)
	}
	if e = r.Check(ctx); e != nil {
		t.Fatal(e)
	}
}

func TestFullStateBridgeSignedRuntimeNoRedelivery(t *testing.T) {
	r, _, _, priv, _, _ := joinFixture(t)
	ctx := context.Background()
	runtime := fmt.Sprintf("%064x", 42)
	signHeartbeat := func(epoch, sequence int64, private ed25519.PrivateKey) BridgeRuntimeHeartbeat {
		b := BridgeRuntimeHeartbeat{Proof: NodeProof{NodeID: "node1", IdentityEpoch: 1}, RuntimeID: runtime, Epoch: epoch, Sequence: sequence}
		b.Proof = signJoinProof(t, private, "runtime", 1, bridgeRuntimePayload(b))
		return b
	}
	first := signHeartbeat(1, 1, priv)
	if e := r.HeartbeatBridgeRuntime(ctx, first); e != nil {
		t.Fatal(e)
	}
	if e := r.HeartbeatBridgeRuntime(ctx, first); !errors.Is(e, ErrReplay) {
		t.Fatalf("heartbeat nonce replay: %v", e)
	}
	c := model.ServerBridgeControlCommand{ServerID: "node1", RuntimeID: runtime, RuntimeEpoch: 1, Type: "broadcast", Payload: map[string]string{"message": "maintenance"}, RequestedBy: "owner", IdempotencyKey: "request-001", ExpiresAt: time.Now().Add(time.Minute)}
	created, yes, e := r.CreateBridgeCommand(ctx, c)
	if e != nil || !yes {
		t.Fatalf("enqueue: %+v %v", created, e)
	}
	// Lost network response can replay the idempotency key; the original request must be exactly identical.
	same, yes, e := r.CreateBridgeCommand(ctx, c)
	if e != nil || yes || same.ID != created.ID {
		t.Fatalf("enqueue replay: %+v %v", same, e)
	}
	c.Payload = map[string]string{"message": "danger"}
	if _, _, e = r.CreateBridgeCommand(ctx, c); !errors.Is(e, ErrDurableIdempotency) {
		t.Fatalf("changed request accepted: %v", e)
	}
	signLease := func(worker string) NodeProof {
		return signJoinProof(t, priv, "control-lease", 1, bridgeLeasePayload(runtime, 1, worker, 0, time.Second))
	}
	lease, e := r.LeaseBridgeCommand(ctx, signLease("worker-123"), runtime, 1, "worker-123", 0, time.Second)
	if e != nil || lease.Status != "leased" || len(lease.LeaseToken) != 64 {
		t.Fatalf("lease: %+v %v", lease, e)
	}
	resume, e := r.LeaseBridgeCommand(ctx, signLease("worker-123"), runtime, 1, "worker-123", 0, time.Second)
	if e != nil || resume.LeaseToken != lease.LeaseToken {
		t.Fatalf("resume changed lease: %+v %v", resume, e)
	}
	badToken := fmt.Sprintf("%064x", 1)
	badProof := signJoinProof(t, priv, "control-ack", 1, bridgeAckPayload(lease.ID, runtime, "worker-123", badToken, 1, lease.DeliverySequence, "succeeded", "{}", ""))
	if _, e = r.CompleteBridgeCommand(ctx, badProof, lease.ID, runtime, "worker-123", badToken, 1, lease.DeliverySequence, "succeeded", nil, ""); !errors.Is(e, ErrBridgeUncertain) {
		t.Fatalf("wrong token accepted: %v", e)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, e = r.LeaseBridgeCommand(ctx, signLease("worker-456"), runtime, 1, "worker-456", 0, time.Second); !errors.Is(e, ErrNotFound) {
		t.Fatalf("ambiguous delivery replayed: %v", e)
	}
	indeterminate, e := r.GetBridgeCommand(ctx, lease.ID)
	if e != nil || indeterminate.Status != "indeterminate" {
		t.Fatalf("lost ACK: %+v %v", indeterminate, e)
	}
	staleProof := signJoinProof(t, priv, "control-ack", 1, bridgeAckPayload(lease.ID, runtime, "worker-123", lease.LeaseToken, 1, lease.DeliverySequence, "succeeded", "{}", ""))
	if _, e = r.CompleteBridgeCommand(ctx, staleProof, lease.ID, runtime, "worker-123", lease.LeaseToken, 1, lease.DeliverySequence, "succeeded", nil, ""); !errors.Is(e, ErrBridgeUncertain) {
		t.Fatalf("stale ACK accepted: %v", e)
	}
	second := signHeartbeat(2, 1, priv)
	if e = r.HeartbeatBridgeRuntime(ctx, second); e != nil {
		t.Fatal(e)
	}
	if e = r.Check(ctx); e != nil {
		t.Fatal(e)
	}
}
