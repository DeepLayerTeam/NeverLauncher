package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

type processRole0455 struct {
	name         string
	api, workers bool
}

// В Network HA роли нужно назначать явно: иначе каждый API случайно запускает
// фоновых потребителей, а неправильно настроенный worker может открывать публичные
// маршруты.
func parseProcessRole0455(raw, deployment string) (processRole0455, error) {
	role := strings.ToLower(strings.TrimSpace(raw))
	if role == "" {
		role = "all"
	}
	var r processRole0455
	switch role {
	case "all":
		r = processRole0455{role, true, true}
	case "api":
		r = processRole0455{role, true, false}
	case "worker":
		r = processRole0455{role, false, true}
	case "migrate":
		r = processRole0455{role, false, false}
	default:
		return r, fmt.Errorf("invalid LAUNCHER_PROCESS_ROLE=%q (all|api|worker|migrate)", raw)
	}
	if strings.EqualFold(strings.TrimSpace(deployment), "network-ha") && role == "all" {
		return r, errors.New("network-ha requires explicit LAUNCHER_PROCESS_ROLE=api, worker or migrate")
	}
	return r, nil
}

// Процесс только для рабочих задач не имеет HTTP-слушателя на внешнем
// интерфейсе. Проверка здоровья Docker может обращаться к localhost /ready.
// Готовность теряется, если перестаёт успешно выполняться устойчивый опрос
// PostgreSQL; одного существования процесса недостаточно.
func workerReady0455(last *atomic.Int64, now time.Time) bool {
	n := last.Load()
	return n > 0 && now.Sub(time.Unix(0, n)) >= 0 && now.Sub(time.Unix(0, n)) < 15*time.Second
}

func workerProbeHandler0455(last *atomic.Int64, backend http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("alive\n"))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		// Телеметрия рабочего процесса только на loopback для авторизованных
		// локальных инструментов расследования инцидентов.
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if workerReady0455(last, time.Now()) {
			_, _ = fmt.Fprint(w, "# HELP launcher_worker_poll_fresh Last durable PostgreSQL poll was recent\n# TYPE launcher_worker_poll_fresh gauge\nlauncher_worker_poll_fresh 1\n")
		} else {
			_, _ = fmt.Fprint(w, "# TYPE launcher_worker_poll_fresh gauge\nlauncher_worker_poll_fresh 0\n")
		}
	})
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		if !workerReady0455(last, time.Now()) {
			http.Error(w, "worker has no recent successful PostgreSQL poll", http.StatusServiceUnavailable)
			return
		}
		if backend != nil {
			// Не объявляйте работающий worker готовым, когда недоступны Redis/S3,
			// федерация или PostgreSQL: используйте реальную проверку готовности Backend.
			backend.ServeHTTP(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})
	return mux
}

func runWorkerProbe0455(addr string, last *atomic.Int64, backend http.Handler) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid LAUNCHER_HTTP_ADDR: %w", err)
	}
	// Всегда ограничивайте слушатель loopback, даже если HTTP_ADDR равно 0.0.0.0.
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		return err
	}
	slog.Info("worker_local_probe_started", "port", port)
	server := &http.Server{Handler: workerProbeHandler0455(last, backend), ReadHeaderTimeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	select {
	case <-signals:
	case err := <-done:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return errors.New("worker probe unexpectedly stopped")
	}
	return server.Close()
}
