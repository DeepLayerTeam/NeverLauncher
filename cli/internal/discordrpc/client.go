// Package discordrpc sends Rich Presence over Discord's local IPC protocol.
// It does not implement the discontinued Game SDK peer/lobby API.
package discordrpc

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxFrame = 1 << 20

// ErrDisconnected denotes a dropped desktop IPC session, not an RPC rejection.
var ErrDisconnected = errors.New("Discord desktop IPC disconnected")

var snowflake = regexp.MustCompile(`^[0-9]{17,20}$`)

type Button struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}
type Activity struct {
	State      string   `json:"state,omitempty"`
	Details    string   `json:"details,omitempty"`
	Buttons    []Button `json:"buttons,omitempty"`
	Timestamps *struct {
		Start int64 `json:"start,omitempty"`
	} `json:"timestamps,omitempty"`
}

func (a Activity) Validate() error {
	if len([]rune(a.State)) > 128 || len([]rune(a.Details)) > 128 {
		return errors.New("Discord state/details exceed 128 characters")
	}
	if len(a.Buttons) > 2 {
		return errors.New("Discord supports at most two activity buttons")
	}
	for _, b := range a.Buttons {
		if len([]rune(b.Label)) < 1 || len([]rune(b.Label)) > 32 || !strings.HasPrefix(b.URL, "https://") {
			return errors.New("activity buttons require label <=32 and HTTP(S) URL")
		}
	}
	return nil
}
func ipcPaths() []string {
	if runtime.GOOS == "windows" {
		out := make([]string, 0, 10)
		for i := 0; i < 10; i++ {
			out = append(out, fmt.Sprintf(`\\.\pipe\discord-ipc-%d`, i))
		}
		return out
	}
	dirs := []string{os.Getenv("XDG_RUNTIME_DIR"), os.Getenv("TMPDIR"), os.Getenv("TMP"), os.Getenv("TEMP"), "/tmp"}
	out := []string{}
	for _, d := range dirs {
		if d == "" {
			continue
		}
		for i := 0; i < 10; i++ {
			out = append(out, filepath.Join(d, fmt.Sprintf("discord-ipc-%d", i)))
		}
	}
	return out
}
func dial() (io.ReadWriteCloser, error) {
	for _, p := range ipcPaths() {
		if runtime.GOOS == "windows" {
			f, err := os.OpenFile(p, os.O_RDWR, 0)
			if err == nil {
				return f, nil
			}
		} else {
			c, err := net.DialTimeout("unix", p, 750*time.Millisecond)
			if err == nil {
				return c, nil
			}
		}
	}
	return nil, errors.New("Discord desktop IPC unavailable")
}
func writeFrame(w io.Writer, opcode uint32, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	if len(data) > maxFrame {
		return errors.New("Discord IPC frame too large")
	}
	var header [8]byte
	binary.LittleEndian.PutUint32(header[:4], opcode)
	binary.LittleEndian.PutUint32(header[4:], uint32(len(data)))
	if err := writeFull(w, header[:]); err != nil {
		return err
	}
	return writeFull(w, data)
}
func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func readFrame(r io.Reader) (uint32, map[string]json.RawMessage, error) {
	var header [8]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	size := binary.LittleEndian.Uint32(header[4:])
	if size > maxFrame {
		return 0, nil, errors.New("Discord IPC oversized frame")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return 0, nil, err
	}
	var v map[string]json.RawMessage
	if err := json.Unmarshal(data, &v); err != nil {
		return 0, nil, err
	}
	return binary.LittleEndian.Uint32(header[:4]), v, nil
}

type Client struct {
	mu    sync.Mutex
	conn  io.ReadWriteCloser
	nonce uint64
}

func (c *Client) Close() error { c.mu.Lock(); defer c.mu.Unlock(); return c.conn.Close() }
func Connect(ctx context.Context, appID string) (*Client, error) {
	if !snowflake.MatchString(appID) {
		return nil, errors.New("Discord application ID must be a decimal snowflake")
	}
	raw, err := dial()
	if err != nil {
		return nil, err
	}
	c := &Client{conn: raw}
	if err := c.handshake(ctx, appID); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return c, nil
}
func (c *Client) handshake(ctx context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := deadline(c.conn, ctx); err != nil {
		return err
	}
	if err := writeFrame(c.conn, 0, map[string]any{"v": 1, "client_id": id}); err != nil {
		return err
	}
	for i := 0; i < 8; i++ {
		op, p, err := readFrame(c.conn)
		if err != nil {
			return err
		}
		if op == 2 {
			return errors.New("Discord closed IPC handshake")
		}
		if string(p["evt"]) == `"ERROR"` {
			return fmt.Errorf("Discord handshake rejected: %s", p["data"])
		}
		if op == 1 && string(p["evt"]) == `"READY"` {
			return nil
		}
	}
	return errors.New("Discord IPC READY not received")
}
func deadline(raw io.ReadWriteCloser, ctx context.Context) error {
	if c, ok := raw.(interface{ SetDeadline(time.Time) error }); ok {
		d := time.Now().Add(5 * time.Second)
		if t, ok := ctx.Deadline(); ok && t.Before(d) {
			d = t
		}
		return c.SetDeadline(d)
	}
	return nil
}
func (c *Client) SetActivity(ctx context.Context, activity *Activity) error {
	if activity != nil {
		if err := activity.Validate(); err != nil {
			return err
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := deadline(c.conn, ctx); err != nil {
		return err
	}
	c.nonce++
	nonce := strconv.FormatUint(c.nonce, 10)
	args := map[string]any{"pid": os.Getpid(), "activity": activity}
	req := map[string]any{"cmd": "SET_ACTIVITY", "nonce": nonce, "args": args}
	if err := writeFrame(c.conn, 1, req); err != nil {
		return err
	}
	for i := 0; i < 16; i++ {
		op, p, err := readFrame(c.conn)
		if err != nil {
			return err
		}
		if op == 2 {
			return ErrDisconnected
		}
		if string(p["nonce"]) != `"`+nonce+`"` {
			continue
		}
		if string(p["evt"]) == `"ERROR"` {
			return fmt.Errorf("Discord SET_ACTIVITY rejected: %s", p["data"])
		}
		if string(p["cmd"]) == `"SET_ACTIVITY"` {
			return nil
		}
	}
	return errors.New("Discord activity acknowledgement not received")
}
