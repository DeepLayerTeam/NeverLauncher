package discordrpc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestActivityValidation(t *testing.T) {
	a := Activity{Details: "Launcher", Buttons: []Button{{Label: "Server", URL: "https://example.org"}}}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	a.Buttons[0].URL = "javascript:alert(1)"
	if a.Validate() == nil {
		t.Fatal("unsafe button link")
	}
	a.Buttons = nil
	a.State = strings.Repeat("S", 129)
	if a.Validate() == nil {
		t.Fatal("overlong state")
	}
}
func TestLocalDiscordSession(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows named-pipe mock requires Windows IPC harness")
	}
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)
	listener, err := net.Listen("unix", filepath.Join(dir, "discord-ipc-0"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	errCh := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
		op, msg, err := readFrame(c)
		if err != nil || op != 0 || string(msg["client_id"]) != `"123456789012345678"` {
			errCh <- fmt.Errorf("handshake %d %v %v", op, msg, err)
			return
		}
		if err := writeFrame(c, 1, map[string]any{"cmd": "DISPATCH", "evt": "READY", "data": map[string]any{}}); err != nil {
			errCh <- err
			return
		}
		op, msg, err = readFrame(c)
		if err != nil || op != 1 || string(msg["cmd"]) != `"SET_ACTIVITY"` {
			errCh <- fmt.Errorf("activity %d %v %v", op, msg, err)
			return
		}
		var args struct {
			PID      int      `json:"pid"`
			Activity Activity `json:"activity"`
		}
		if err := json.Unmarshal(msg["args"], &args); err != nil || args.PID <= 0 || args.Activity.State != "Playing Minecraft" {
			errCh <- fmt.Errorf("bad payload: %#v %v", args, err)
			return
		}
		nonce := msg["nonce"]
		var nonceString string
		_ = json.Unmarshal(nonce, &nonceString)
		errCh <- writeFrame(c, 1, map[string]any{"cmd": "SET_ACTIVITY", "nonce": nonceString, "data": map[string]any{}})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, err := Connect(ctx, "123456789012345678")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetActivity(ctx, &Activity{State: "Playing Minecraft"}); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}
func TestBadApplicationID(t *testing.T) {
	if _, err := Connect(context.Background(), "no"); err == nil {
		t.Fatal("invalid app ID accepted")
	}
}
func TestRejectOversizedFrame(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "frame")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := writeFrame(f, 1, map[string]any{"text": strings.Repeat("a", maxFrame)}); err == nil {
		t.Fatal("oversized frame accepted")
	}
}
