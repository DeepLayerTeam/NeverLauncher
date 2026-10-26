package extensionhost

import (
	"bytes"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCLIOutput03113SharesBothStreams(t *testing.T) {
	policy := &model.ExtensionSandboxPolicy{Mode: "isolated", MaxOutputBytes: 8}
	st := &processState{}
	var dst bytes.Buffer
	var called atomic.Int32
	var once sync.Once
	abort := func() { called.Add(1) }
	a := &cliOutputWriter03113{st: st, target: &dst, policy: policy, abort: abort, once: &once}
	b := &cliOutputWriter03113{st: st, target: &dst, policy: policy, abort: abort, once: &once}
	if n, err := a.Write([]byte("1234")); n != 4 || err != nil {
		t.Fatal(n, err)
	}
	if n, err := b.Write([]byte("5678")); n != 4 || err != nil {
		t.Fatal(n, err)
	}
	for i := 0; i < 5; i++ {
		if n, err := b.Write([]byte("overflow")); n != 8 || err != nil {
			t.Fatal(n, err)
		}
	}
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) && called.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	if called.Load() != 1 || dst.String() != "12345678" {
		t.Fatalf("abort=%d content=%q", called.Load(), dst.String())
	}
}
