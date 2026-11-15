package discordrpc

import (
	"context"
	"io"
	"testing"
	"time"
)

type testIPCConn interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
}
type testIPCListener interface {
	Accept() (testIPCConn, error)
	Close() error
}

func testDiscordEndpoint(t *testing.T, count int) (testIPCListener, func(context.Context, string) (*Client, error)) {
	t.Helper()
	listener, paths := newTestIPCListener(t, count)
	return listener, func(ctx context.Context, id string) (*Client, error) {
		return connectWith(ctx, id, func() (io.ReadWriteCloser, error) { return dialPaths(paths) })
	}
}
