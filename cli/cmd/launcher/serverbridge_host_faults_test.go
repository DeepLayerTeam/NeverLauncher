package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Потерянный ACK или тайм-аут действия хоста: исходная квитанция с неопределённым результатом сохраняется после
// перезапуска агента и блокирует ДРУГИЕ ключи идемпотентности, не только первоначальный.
func TestRemoteFaultUnknownBlocksNewAction04112(t *testing.T) {
	a, id, root := remoteFixture0284(t)
	token := remoteTokenFixture0284(t, id, "host.start", "host.stop", "host.status")
	var effects atomic.Int32
	a.execute = func(string) (json.RawMessage, error) {
		effects.Add(1)
		return nil, os.ErrDeadlineExceeded // внешнее побочное действие уже могло произойти
	}
	call := func(agent *remoteAgent0284, action, key string) int {
		return remoteRequest0284(t, agent, token, http.MethodPost, "/v1/host/commands", action, key, "127.0.0.1:2190").Code
	}
	if code := call(a, "start", "first-unknown-04112-0001"); code != http.StatusConflict {
		t.Fatalf("Первое превышение времени ожидания: %d", code)
	}
	if code := call(a, "stop", "new-action-04112-000001"); code != http.StatusConflict {
		t.Fatalf("Другой ключ позволил обойти неопределённое состояние: %d", code)
	}
	if effects.Load() != 1 {
		t.Fatalf("Побочное действие выполнено %d раз", effects.Load())
	}
	restarted, err := remoteNewAgent0284(root, id, []string{"127.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	restarted.execute = func(string) (json.RawMessage, error) { effects.Add(1); return nil, nil }
	if code := call(restarted, "start", "first-unknown-04112-0001"); code != http.StatusConflict {
		t.Fatalf("Повтор после потери подтверждения ACK: %d", code)
	}
	if code := call(restarted, "stop", "new-action-04112-000001"); code != http.StatusConflict {
		t.Fatalf("Перезапущенный агент обошёл неопределённость: %d", code)
	}
	if effects.Load() != 1 {
		t.Fatalf("Физическое действие выполнено повторно: %d", effects.Load())
	}
}

func TestRemoteFaultReadOnlyReceipt04112(t *testing.T) {
	a, id, _ := remoteFixture0284(t)
	token := remoteTokenFixture0284(t, id, "host.start", "host.status")
	var effects atomic.Int32
	a.execute = func(string) (json.RawMessage, error) { effects.Add(1); return json.RawMessage(`{"ok":true}`), nil }
	key := "completed-command-04112-001"
	first := remoteRequest0284(t, a, token, http.MethodPost, "/v1/host/commands", "start", key, "127.0.0.1:1000")
	if first.Code != http.StatusOK {
		t.Fatalf("execute %d %s", first.Code, first.Body.String())
	}
	for i := 0; i < 3; i++ {
		r := remoteRequest0284(t, a, token, http.MethodGet, "/v1/host/receipts/"+key, "", "", "127.0.0.1:1000")
		if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"succeeded"`) {
			t.Fatalf("ответ GET: %d: %s", r.Code, r.Body.String())
		}
	}
	if effects.Load() != 1 {
		t.Fatalf("Запрос квитанции повторно выполнил действие: %d", effects.Load())
	}
	otherSubject, err := remoteIssue0284(id, "another-operator", []string{"host.start", "host.status"}, []string{"127.0.0.0/8"}, time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if r := remoteRequest0284(t, a, otherSubject, http.MethodGet, "/v1/host/receipts/"+key, "", "", "127.0.0.1:1000"); r.Code != http.StatusForbidden {
		t.Fatalf("Выдана квитанция чужого запроса: %d", r.Code)
	}
	if r := remoteRequest0284(t, a, token, http.MethodGet, "/v1/host/receipts/missing-command-04112-001", "", "", "127.0.0.1:1000"); r.Code != http.StatusNotFound {
		t.Fatalf("Отсутствует квитанция: %d", r.Code)
	}
}

func TestRemoteFaultCorruptJournalFailClosed04112(t *testing.T) {
	a, id, root := remoteFixture0284(t)
	token := remoteTokenFixture0284(t, id, "host.start")
	if err := os.WriteFile(filepath.Join(remoteDir0284(root), "commands", "not-an-ack.json"), []byte(`{"state":"succeeded"}`), 0600); err != nil {
		t.Fatal(err)
	}
	var count atomic.Int32
	a.execute = func(string) (json.RawMessage, error) { count.Add(1); return nil, nil }
	resp := remoteRequest0284(t, a, token, http.MethodPost, "/v1/host/commands", "start", "valid-command-04112-001", "127.0.0.1:1000")
	if resp.Code != http.StatusServiceUnavailable || count.Load() != 0 {
		t.Fatalf("Повреждённый журнал допустил команду: %d, действий=%d", resp.Code, count.Load())
	}
}

func TestRemoteFaultKernelSplitBrain04112(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("платформа не поддерживает единственный экземпляр на уровне ядра")
	}
	_, id, root := remoteFixture0284(t)
	dir := remoteDir0284(root)
	// Имитируйте сбой агента с устаревшей JSON-идентичностью и двумя конкурентами,
	// одновременно восстанавливающими её на разных портах прослушивания.
	stale, err := json.Marshal(remoteLease0284{PID: 99999999, Identity: "dead-session", NodeID: id.NodeID})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent.lock"), stale, 0600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var wins atomic.Int32
	releases := make(chan func(), 2)
	ready := make(chan struct{})
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ready
			release, err := remoteAcquireLease0284(dir, id.NodeID)
			if err == nil {
				wins.Add(1)
				releases <- release
			}
		}()
	}
	close(ready)
	wg.Wait()
	close(releases)
	if wins.Load() != 1 {
		t.Fatalf("Конфликт владения: %d агентов получили один корневой каталог", wins.Load())
	}
	for release := range releases {
		release()
	}
	release, err := remoteAcquireLease0284(dir, id.NodeID)
	if err != nil {
		t.Fatalf("Агент не может перезапуститься после корректного освобождения: %v", err)
	}
	release()
}

// Конкурирующие операторы с разными ключами идемпотентности не должны обходить сохранённую
// неопределённую операцию лишь потому, что их действия различаются.
func TestRemoteFaultConcurrentUnknownDifferentKeys04112(t *testing.T) {
	a, id, _ := remoteFixture0284(t)
	token := remoteTokenFixture0284(t, id, "host.start", "host.stop", "host.restart")
	var executions atomic.Int32
	a.execute = func(string) (json.RawMessage, error) {
		executions.Add(1)
		time.Sleep(15 * time.Millisecond)
		return nil, os.ErrDeadlineExceeded
	}
	const n = 16
	var wg sync.WaitGroup
	ready := make(chan struct{})
	responses := make(chan int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-ready
			action := []string{"start", "stop", "restart"}[i%3]
			key := fmt.Sprintf("concurrent-fault-04112-%04d", i)
			responses <- remoteRequest0284(t, a, token, http.MethodPost, "/v1/host/commands", action, key, "127.0.0.1:2222").Code
		}(i)
	}
	close(ready)
	wg.Wait()
	close(responses)
	for code := range responses {
		if code != http.StatusConflict {
			t.Fatalf("Неожиданный ответ параллельного запроса: %d", code)
		}
	}
	if executions.Load() != 1 {
		t.Fatalf("Параллельная неопределённая операция привела к %d физическим действиям", executions.Load())
	}
}
