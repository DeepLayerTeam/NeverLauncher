package neverextensions

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type EventEnvelope struct {
	ProtocolVersion string            `json:"protocolVersion"`
	Subscription    EventSubscription `json:"subscription"`
	Event           json.RawMessage   `json:"event"`
}

type HookResult struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason,omitempty"`
}
type EventHandler func(context.Context, EventEnvelope) error
type HookHandler func(context.Context, EventEnvelope) (HookResult, error)

type CallbackServer struct {
	server   *http.Server
	listener net.Listener
	URL      string
}

func newCallbackServer(token string, events EventHandler, hooks HookHandler) (*CallbackServer, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return false
		}
		return true
	}
	decode := func(w http.ResponseWriter, r *http.Request) (EventEnvelope, bool) {
		var env EventEnvelope
		data, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		if err != nil || len(data) > 1<<20 || json.Unmarshal(data, &env) != nil || strings.TrimSpace(env.ProtocolVersion) == "" {
			http.Error(w, "недопустимый событие конверт", http.StatusBadRequest)
			return EventEnvelope{}, false
		}
		return env, true
	}
	mux.HandleFunc("POST /v1/events", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		env, ok := decode(w, r)
		if !ok {
			return
		}
		if events == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err := events(r.Context(), env); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/hooks", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		env, ok := decode(w, r)
		if !ok {
			return
		}
		result := HookResult{Allow: true}
		if hooks != nil {
			var err error
			result, err = hooks(r.Context(), env)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	s := &CallbackServer{server: server, listener: ln, URL: "http://" + ln.Addr().String()}
	go func() {
		err := server.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
		}
	}()
	return s, nil
}

func (s *CallbackServer) Close(ctx context.Context) error {
	if s == nil || s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}
