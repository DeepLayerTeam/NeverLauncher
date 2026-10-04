package serverbridgeha

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeRedis01911 struct {
	ln     net.Listener
	mu     sync.Mutex
	values map[string]string
	closed chan struct{}
}

func newFakeRedis01911(t *testing.T) *fakeRedis01911 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRedis01911{ln: ln, values: map[string]string{}, closed: make(chan struct{})}
	go f.serve()
	t.Cleanup(func() { _ = ln.Close(); <-f.closed })
	return f
}
func (f *fakeRedis01911) url() string { return "redis://" + f.ln.Addr().String() + "/0" }
func (f *fakeRedis01911) serve() {
	defer close(f.closed)
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go func() { defer c.Close(); f.handle(c) }()
	}
}
func (f *fakeRedis01911) handle(c net.Conn) {
	raw, err := readRESP(bufio.NewReader(c))
	if err != nil {
		return
	}
	list, ok := raw.([]any)
	if !ok || len(list) == 0 {
		return
	}
	args := make([]string, len(list))
	for i, v := range list {
		args[i], _ = v.(string)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch strings.ToUpper(args[0]) {
	case "PING":
		fmt.Fprint(c, "+PONG\r\n")
	case "SET":
		if len(args) >= 3 {
			f.values[args[1]] = args[2]
		}
		fmt.Fprint(c, "+OK\r\n")
	case "GET":
		v, ok := f.values[args[1]]
		if !ok {
			fmt.Fprint(c, "$-1\r\n")
			return
		}
		fmt.Fprintf(c, "$%d\r\n%s\r\n", len(v), v)
	case "EVAL":
		key, value := args[3], args[4]
		if strings.Contains(args[1], "SET',KEYS[1]") {
			old, exists := f.values[key]
			if !exists || old == value {
				f.values[key] = value
				fmt.Fprint(c, ":1\r\n")
			} else {
				fmt.Fprint(c, ":0\r\n")
			}
			return
		}
		if old, exists := f.values[key]; exists && old == value {
			delete(f.values, key)
			fmt.Fprint(c, ":1\r\n")
		} else {
			fmt.Fprint(c, ":0\r\n")
		}
	default:
		fmt.Fprint(c, "-ERR unsupported\r\n")
	}
}

func TestRedisCoordinatorFencesCommandOwnership01911(t *testing.T) {
	fake := newFakeRedis01911(t)
	coordinator, err := NewRedis(fake.url())
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	ownerA, tokenA := "0123456789abcdef0123456789abcdef", "lease_A_0123456789abcdef"
	ownerB, tokenB := "fedcba9876543210fedcba9876543210", "lease_B_0123456789abcdef"
	ok, err := coordinator.AcquireCommandLease(context.Background(), "paper-main", "ctl-1", ownerA, tokenA, 30*time.Second)
	if err != nil || !ok {
		t.Fatalf("first acquire: ok=%v err=%v", ok, err)
	}
	ok, err = coordinator.AcquireCommandLease(context.Background(), "paper-main", "ctl-1", ownerA, tokenA, 30*time.Second)
	if err != nil || !ok {
		t.Fatalf("same owner renewal: ok=%v err=%v", ok, err)
	}
	ok, err = coordinator.AcquireCommandLease(context.Background(), "paper-main", "ctl-1", ownerB, tokenB, 30*time.Second)
	if err != nil || ok {
		t.Fatalf("competing acquire must be fenced: ok=%v err=%v", ok, err)
	}
	verified, err := coordinator.VerifyCommandLease(context.Background(), "paper-main", "ctl-1", ownerA, tokenA)
	if err != nil || !verified {
		t.Fatalf("verify owner A: %v %v", verified, err)
	}
	if err := coordinator.ReleaseCommandLease(context.Background(), "paper-main", "ctl-1", ownerB, tokenB); err != nil {
		t.Fatal(err)
	}
	verified, _ = coordinator.VerifyCommandLease(context.Background(), "paper-main", "ctl-1", ownerA, tokenA)
	if !verified {
		t.Fatal("non-owner release removed lease")
	}
	if err := coordinator.ReleaseCommandLease(context.Background(), "paper-main", "ctl-1", ownerA, tokenA); err != nil {
		t.Fatal(err)
	}
	verified, _ = coordinator.VerifyCommandLease(context.Background(), "paper-main", "ctl-1", ownerA, tokenA)
	if verified {
		t.Fatal("owner release did not remove lease")
	}
	if err := coordinator.TouchChannel(context.Background(), ChannelPresence{ReplicaID: "api-1", ServerID: "paper-main", RuntimeID: strings.Repeat("a", 64), ChannelID: ownerA, ResumeAfter: 42, BackendAddress: "api-a:8080"}, 15*time.Second); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	found := false
	for k, v := range fake.values {
		if strings.Contains(k, "ha:channel") && strings.Contains(v, "42") {
			found = true
		}
	}
	if !found {
		t.Fatal("channel presence was not persisted to Redis")
	}
}
