package extensionhost

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

// An RPC probe, memory monitor and heartbeat timeout can race. A later
// completion must never overwrite the first actionable termination reason.
func TestSupervisorConcurrentTerminalFailure03012(t *testing.T) {
	s := New(Config{}, repository.NewMemoryRepository("http://localhost"), nil)
	st := &processState{state: "running"}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.failProcess(st, "Java RPC unresponsive after 3 probes", false) }()
	}
	wg.Wait()
	s.failProcess(st, "heartbeat timeout", false)
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.state != "failing" || !st.terminationInitiated || st.expectedStop || st.lastError != "Java RPC unresponsive after 3 probes" {
		t.Fatalf("terminal transition was not idempotent: state=%s cause=%q", st.state, st.lastError)
	}
}

func TestSupervisorStopCannotBeOverriddenByLateProbe03012(t *testing.T) {
	s := New(Config{}, repository.NewMemoryRepository("http://localhost"), nil)
	st := &processState{state: "stopping", expectedStop: true}
	s.failProcess(st, "late RPC timeout", false)
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.state != "stopping" || !st.expectedStop || st.lastError != "" {
		t.Fatal("late health probe overrode an intentional stop")
	}
}

// The existing fixture exercises the genuine Go supervisor, live Java JAR,
// RPC token and independent health probes. On a crashed JVM the status must
// retain the RPC failure, not a platform-specific kill/signal message.
func TestSupervisorPreservesJvmHangCause03012(t *testing.T) {
	host, install, key := javaHostFixture0304(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := host.StartInstallation(ctx, install); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		go func() {
			_, _ = host.CallJavaRPC0304(ctx, key, "command.invoke", []byte(`{"command":"hang","payload":{}}`))
		}()
	}
	deadline := time.NewTimer(19 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		status, err := host.Get(key)
		if err != nil {
			t.Fatal(err)
		}
		if status.State == "crashed" || status.State == "crashloop" {
			if !strings.Contains(status.LastError, "Java RPC unresponsive") {
				t.Fatalf("missing original failure reason: state=%s err=%q", status.State, status.LastError)
			}
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatalf("hung Java process never terminated: %+v", status)
		}
	}
}
