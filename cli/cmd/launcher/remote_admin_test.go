package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestRemoteGracefulStopWaitsForJournaledRequest0428(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	finish := make(chan struct{})
	var once sync.Once
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(entered) })
		<-finish
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "committed")
	})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- remoteServeManaged0428(ctx, server, listener) }()
	reply := make(chan error, 1)
	go func() {
		client := &http.Client{Timeout: 3 * time.Second}
		resp, e := client.Get("http://" + listener.Addr().String())
		if e != nil {
			reply <- e
			return
		}
		defer resp.Body.Close()
		b, e := io.ReadAll(resp.Body)
		if e == nil && string(b) != "committed" {
			e = io.ErrUnexpectedEOF
		}
		reply <- e
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("Запрос не дошёл до сервера")
	}
	cancel()
	select {
	case err := <-result:
		t.Fatalf("Сервер завершил работу до выполнения запроса: %v", err)
	case <-time.After(60 * time.Millisecond):
	}
	close(finish)
	select {
	case err := <-reply:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Отсутствует ответ на запрос")
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Завершение работы не выполнено")
	}
}
