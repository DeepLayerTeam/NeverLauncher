package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

func TestHostControlValidation0413(t *testing.T) {
	for _, body := range []string{`{"action":"shell"}`, `{"action":"restart","arguments":["rm"]}`, `{"action":"start"} {"action":"stop"}`, `null`, `{}`} {
		r := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
		w := httptest.NewRecorder()
		if _, err := decodeHostAction0413(r, w); err == nil {
			t.Fatalf("unsafe command accepted: %s", body)
		}
	}
	for _, action := range []string{"start", "stop", "restart"} {
		r := httptest.NewRequest("POST", "/", bytes.NewBufferString(`{"action":"`+action+`"}`))
		w := httptest.NewRecorder()
		got, err := decodeHostAction0413(r, w)
		if err != nil || got != action {
			t.Fatalf("%q: %q %v", action, got, err)
		}
	}
	if hostKey0413.MatchString("bad") || hostKey0413.MatchString("aaa;rm -rf") || !hostKey0413.MatchString("host-action-key-00001") {
		t.Fatal("unsafe host key validation")
	}
}
func TestHostControlBridgeCorrelation0413(t *testing.T) {
	op := repository.HostOperation0413{CreatedAt: time.Now().Add(-2 * time.Second), BaselineRuntimeID: "old", BaselineRuntimeEpoch: 5}
	node := bridgeServerRecord{Status: "active", RuntimeID: "new", RuntimeEpoch: 6, LastHeartbeatAt: time.Now()}
	if !hostReady0413("restart", op, node) {
		t.Fatal("new bridge runtime not recognized")
	}
	node.RuntimeID = "old"
	if hostReady0413("restart", op, node) {
		t.Fatal("old bridge runtime accepted")
	}
	node.RuntimeID = "new"
	node.LastHeartbeatAt = op.CreatedAt.Add(-time.Second)
	if hostReady0413("start", op, node) {
		t.Fatal("stale bridge heartbeat accepted")
	}
	node.LastHeartbeatAt = time.Now().Add(-3 * time.Minute)
	if hostReady0413("start", op, node) {
		t.Fatal("stale yet once-fresh heartbeat accepted")
	}
	node.LastHeartbeatAt = time.Now().Add(45 * time.Second)
	if hostReady0413("restart", op, node) {
		t.Fatal("future heartbeat accepted")
	}
	if !hostReady0413("stop", op, node) {
		t.Fatal("a stopped host does not require its JVM plugin to remain online")
	}
	b, _ := json.Marshal(hostOperationOutput0413(op, node, false))
	if !bytes.Contains(b, []byte("hostState")) || !bytes.Contains(b, []byte("bridge")) {
		t.Fatal("no correlated state")
	}
}
