package discordrpc

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
)

// Session keeps a local Discord presence usable across desktop IPC restarts.
// SET_ACTIVITY is a replace/clear operation; repeating it after a lost reply
// has no additional side effects. Explicit RPC rejection is never retried.
type Session struct {
	mu     sync.Mutex
	appID  string
	client *Client
	closed bool
}

func NewSession(ctx context.Context, applicationID string) (*Session, error) {
	client, err := Connect(ctx, applicationID)
	if err != nil {
		return nil, err
	}
	return &Session{appID: applicationID, client: client}, nil
}

func connectionLost(err error) bool {
	if errors.Is(err, ErrDisconnected) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr)
}

func (s *Session) SetActivity(ctx context.Context, activity *Activity) error {
	if activity != nil {
		if err := activity.Validate(); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.client == nil {
		client, err := Connect(ctx, s.appID)
		if err != nil {
			return err
		}
		s.client = client
	}
	err := s.client.SetActivity(ctx, activity)
	if err == nil || !connectionLost(err) || ctx.Err() != nil {
		return err
	}
	_ = s.client.Close()
	s.client = nil
	replacement, connectErr := Connect(ctx, s.appID)
	if connectErr != nil {
		return connectErr
	}
	s.client = replacement
	return s.client.SetActivity(ctx, activity)
}

func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.client != nil {
		err := s.client.Close()
		s.client = nil
		return err
	}
	return nil
}
