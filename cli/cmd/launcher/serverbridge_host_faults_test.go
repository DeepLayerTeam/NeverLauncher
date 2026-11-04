package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Lost ACK / host-action timeout: the original uncertain receipt survives an
// agent restart and blocks DIFFERENT idempotency keys, not only the old one.
func TestRemoteFaultUnknownBlocksNewAction04112(t *testing.T) {
	a, id, root := remoteFixture0284(t)
	token := remoteTokenFixture0284(t, id, "host.start", "host.stop", "host.status")
	var effects atomic.Int32
	a.execute = func(string) (json.RawMessage, error) {
		effects.Add(1)
		return nil, os.ErrDeadlineExceeded // external side effect may already have happened
	}
	call := func(agent *remoteAgent0284, action, key string) int {
		return remoteRequest0284(t, agent, token, http.MethodPost, "/v1/host/commands", action, key, "127.0.0.1:2190").Code
	}
	if code := call(a, "start", "first-unknown-04112-0001"); code != http.StatusConflict {
		t.Fatalf("first timeout: %d", code)
	}
	if code := call(a, "stop", "new-action-04112-000001"); code != http.StatusConflict {
		t.Fatalf("different key bypassed uncertainty: %d", code)
	}
	if effects.Load() != 1 {
		t.Fatalf("effect ran %d times", effects.Load())
	}
	restarted, err := remoteNewAgent0284(root, id, []string{"127.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	restarted.execute = func(string) (json.RawMessage, error) { effects.Add(1); return nil, nil }
	if code := call(restarted, "start", "first-unknown-04112-0001"); code != http.StatusConflict {
		t.Fatalf("lost ACK replay: %d", code)
	}
	if code := call(restarted, "stop", "new-action-04112-000001"); code != http.StatusConflict {
		t.Fatalf("restarted agent bypassed uncertainty: %d", code)
	}
	if effects.Load() != 1 {
		t.Fatalf("replayed physical effect %d", effects.Load())
	}
}

func TestRemoteFaultReadOnlyReceipt04112(t *testing.T) {
	a, id, _ := remoteFixture0284(t)
	token := remoteTokenFixture0284(t, id, "host.start", "host.status")
	var effects atomic.Int32
	a.execute = func(string) (json.RawMessage, error) { effects.Add(1); return json.RawMessage(`{"ok":true}`), nil }
	key := "completed-command-04112-001"
	first := remoteRequest0284(t, a, token, http.MethodPost, "/v1/host/commands", "start", key, "127.0.0.1:1000")
	if first.Code != http.StatusOK {
		t.Fatalf("execute %d %s", first.Code, first.Body.String())
	}
	for i := 0; i < 3; i++ {
		r := remoteRequest0284(t, a, token, http.MethodGet, "/v1/host/receipts/"+key, "", "", "127.0.0.1:1000")
		if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"succeeded"`) {
			t.Fatalf("GET %d: %s", r.Code, r.Body.String())
		}
	}
	if effects.Load() != 1 {
		t.Fatalf("receipt lookup reexecuted action %d", effects.Load())
	}
	otherSubject, err := remoteIssue0284(id, "another-operator", []string{"host.start", "host.status"}, []string{"127.0.0.0/8"}, time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if r := remoteRequest0284(t, a, otherSubject, http.MethodGet, "/v1/host/receipts/"+key, "", "", "127.0.0.1:1000"); r.Code != http.StatusForbidden {
		t.Fatalf("foreign receipt exposed %d", r.Code)
	}
	if r := remoteRequest0284(t, a, token, http.MethodGet, "/v1/host/receipts/missing-command-04112-001", "", "", "127.0.0.1:1000"); r.Code != http.StatusNotFound {
		t.Fatalf("missing receipt: %d", r.Code)
	}
}

func TestRemoteFaultCorruptJournalFailClosed04112(t *testing.T) {
	a, id, root := remoteFixture0284(t)
	token := remoteTokenFixture0284(t, id, "host.start")
	if err := os.WriteFile(filepath.Join(remoteDir0284(root), "commands", "not-an-ack.json"), []byte(`{"state":"succeeded"}`), 0600); err != nil {
		t.Fatal(err)
	}
	var count atomic.Int32
	a.execute = func(string) (json.RawMessage, error) { count.Add(1); return nil, nil }
	resp := remoteRequest0284(t, a, token, http.MethodPost, "/v1/host/commands", "start", "valid-command-04112-001", "127.0.0.1:1000")
	if resp.Code != http.StatusServiceUnavailable || count.Load() != 0 {
		t.Fatalf("corrupt journal allowed command: %d effects=%d", resp.Code, count.Load())
	}
}

func TestRemoteFaultKernelSplitBrain04112(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unsupported kernel singleton platform")
	}
	_, id, root := remoteFixture0284(t)
	dir := remoteDir0284(root)
	// Simulate a crashed agent with a stale JSON identity and two contenders
	// attempting to recover it at the same time on different listen ports.
	stale, err := json.Marshal(remoteLease0284{PID: 99999999, Identity: "dead-session", NodeID: id.NodeID})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent.lock"), stale, 0600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var wins atomic.Int32
	releases := make(chan func(), 2)
	ready := make(chan struct{})
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ready
			release, err := remoteAcquireLease0284(dir, id.NodeID)
			if err == nil {
				wins.Add(1)
				releases <- release
			}
		}()
	}
	close(ready)
	wg.Wait()
	close(releases)
	if wins.Load() != 1 {
		t.Fatalf("split-brain: %d agents obtained same root", wins.Load())
	}
	for release := range releases {
		release()
	}
	release, err := remoteAcquireLease0284(dir, id.NodeID)
	if err != nil {
		t.Fatalf("agent cannot restart after clean release: %v", err)
	}
	release()
}

// Concurrent operators with different idempotency keys must not bypass a
// persisted uncertain operation just because their actions differ.
func TestRemoteFaultConcurrentUnknownDifferentKeys04112(t *testing.T) {
	a, id, _ := remoteFixture0284(t)
	token := remoteTokenFixture0284(t, id, "host.start", "host.stop", "host.restart")
	var executions atomic.Int32
	a.execute = func(string) (json.RawMessage, error) {
		executions.Add(1)
		time.Sleep(15 * time.Millisecond)
		return nil, os.ErrDeadlineExceeded
	}
	const n = 16
	var wg sync.WaitGroup
	ready := make(chan struct{})
	responses := make(chan int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-ready
			action := []string{"start", "stop", "restart"}[i%3]
			key := fmt.Sprintf("concurrent-fault-04112-%04d", i)
			responses <- remoteRequest0284(t, a, token, http.MethodPost, "/v1/host/commands", action, key, "127.0.0.1:2222").Code
		}(i)
	}
	close(ready)
	wg.Wait()
	close(responses)
	for code := range responses {
		if code != http.StatusConflict {
			t.Fatalf("unexpected concurrent response %d", code)
		}
	}
	if executions.Load() != 1 {
		t.Fatalf("concurrent unknown caused %d physical actions", executions.Load())
	}
}
