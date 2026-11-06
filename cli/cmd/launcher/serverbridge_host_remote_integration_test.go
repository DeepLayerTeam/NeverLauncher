//go:build linux

package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRemoteControlSystemdReadyAndDrain0498(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "notify.sock")
	unix, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close()
	t.Setenv("NOTIFY_SOCKET", socket)
	t.Setenv("WATCHDOG_USEC", "")
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })}
	go func() { done <- remoteServeManaged0428(ctx, server, tcp) }()
	read := func(expect string) {
		t.Helper()
		if err := unix.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 1024)
		n, _, err := unix.ReadFromUnix(b)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b[:n]), expect) {
			t.Fatalf("Уведомление systemd = %q, ожидалось %s", b[:n], expect)
		}
	}
	read("READY=1")
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + tcp.Addr().String() + "/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal(response.StatusCode)
	}
	cancel()
	read("STOPPING=1")
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("удалённый узел не завершил обработку запросов")
	}
	// Отправка готовности должна завершаться ошибкой при неисправном настроенном сокете systemd.
	t.Setenv("NOTIFY_SOCKET", filepath.Join(t.TempDir(), "unavailable.sock"))
	if err := remoteServiceReady0498(); err == nil {
		t.Fatal("подтверждено отсутствие обработчика уведомлений")
	}
	_ = os.Unsetenv("NOTIFY_SOCKET")
}
