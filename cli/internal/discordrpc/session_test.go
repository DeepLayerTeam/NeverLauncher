package discordrpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// This test launches an actual Unix IPC endpoint, then simulates Discord
// restarting after accepting SET_ACTIVITY but before acknowledging it.
func TestSessionRecoversDisconnectedDesktopIPC(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket test; Windows uses named pipes")
	}
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)
	listener, err := net.Listen("unix", filepath.Join(dir, "discord-ipc-0"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	completed := make(chan error, 1)
	go func() {
		for attempt := 0; attempt < 2; attempt++ {
			connection, err := listener.Accept()
			if err != nil {
				completed <- err
				return
			}
			_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
			op, fields, err := readFrame(connection)
			if err != nil || op != 0 || string(fields["client_id"]) != `"123456789012345678"` {
				completed <- fmt.Errorf("invalid IPC handshake %d %v %v", op, fields, err)
				connection.Close()
				return
			}
			if err := writeFrame(connection, 1, map[string]any{"cmd": "DISPATCH", "evt": "READY"}); err != nil {
				completed <- err
				connection.Close()
				return
			}
			op, fields, err = readFrame(connection)
			if err != nil || op != 1 || string(fields["cmd"]) != `"SET_ACTIVITY"` {
				completed <- fmt.Errorf("invalid activity %d %v %v", op, fields, err)
				connection.Close()
				return
			}
			if attempt == 0 {
				// First client was disconnected mid-flight. The second must
				// restore the activity instead of reporting permanent failure.
				connection.Close()
				continue
			}
			err = writeFrame(connection, 1, map[string]any{"cmd": "SET_ACTIVITY", "nonce": "1"})
			connection.Close()
			completed <- err
			return
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	session, err := NewSession(ctx, "123456789012345678")
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.SetActivity(ctx, &Activity{Details: "Server", State: "Playing Minecraft"}); err != nil {
		t.Fatal(err)
	}
	if err := <-completed; err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.SetActivity(ctx, nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed session reused: %v", err)
	}
}
