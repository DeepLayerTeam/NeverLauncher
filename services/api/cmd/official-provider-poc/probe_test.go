package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

func runProbeFixture(t *testing.T, encryption bool) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer listener.Close()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		for i := 0; i < 2; i++ {
			n, err := readVarInt(r)
			if err != nil || n < 0 || n > 1024 {
				return
			}
			b := make([]byte, n)
			if _, err := r.Read(b); err != nil {
				return
			}
		}
		if !encryption {
			_ = writeFrame(conn, []byte{0})
			return
		}
		privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			return
		}
		key, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return
		}
		response := putVarInt(nil, 1)
		response = putVarInt(response, 0) // server ID empty
		response = putVarInt(response, len(key))
		response = append(response, key...)
		response = putVarInt(response, 4)
		response = append(response, 1, 2, 3, 4)
		_ = writeFrame(conn, response)
	}()
	return listener.Addr().String()
}
func TestServerProbeRealPacketHandling(t *testing.T) {
	if err := probeOnlineMode(context.Background(), runProbeFixture(t, true), 767); err != nil {
		t.Fatal(err)
	}
	if err := probeOnlineMode(context.Background(), runProbeFixture(t, false), 767); err == nil {
		t.Fatal("offline server accepted")
	}
	if err := probeOnlineMode(context.Background(), "example.com:bad", 767); err == nil {
		t.Fatal("invalid address accepted")
	}
	if err := probeOnlineMode(context.Background(), "127.0.0.1:25565", 0); err == nil {
		t.Fatal("invalid protocol accepted")
	}
}
func TestPOCRequiresRealSessionserverWhenEnabled(t *testing.T) {
	r := verify(context.Background(), &simulatedProvider{}, options{ClientID: ownClientID, Flow: "browser", RequireOnlineSession: true}, newDiscardWriter())
	if r.Result != "online_session_verified" || r.OnlineModeSession != "verified_live_join_has_joined" {
		t.Fatalf("unexpected report %+v", r)
	}
	if r.Stages[len(r.Stages)-1].Name != "sessionserver_join_has_joined" {
		t.Fatal("missing session proof stage")
	}
}

type discardWriter struct{}

func (discardWriter) Write(b []byte) (int, error) { return len(b), nil }
func newDiscardWriter() discardWriter             { return discardWriter{} }
