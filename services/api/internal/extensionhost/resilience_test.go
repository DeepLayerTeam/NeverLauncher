package extensionhost

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

// RPC-проба, монитор памяти и тайм-аут heartbeat могут состязаться. Позднее
// завершение никогда не должно перезаписывать первую действенную причину
// остановки.
func TestSupervisorConcurrentTerminalFailure03012(t *testing.T) {
	s := New(Config{}, repository.NewMemoryRepository("http://localhost"), nil)
	st := &processState{state: "running"}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.failProcess(st, "Java RPC не отвечает после трёх проверок", false)
		}()
	}
	wg.Wait()
	s.failProcess(st, "heartbeat timeout", false)
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.state != "failing" || !st.terminationInitiated || st.expectedStop || st.lastError != "Java RPC не отвечает после трёх проверок" {
		t.Fatalf("Завершающий переход не идемпотентен: состояние=%s, причина=%q", st.state, st.lastError)
	}
}

func TestSupervisorStopCannotBeOverriddenByLateProbe03012(t *testing.T) {
	s := New(Config{}, repository.NewMemoryRepository("http://localhost"), nil)
	st := &processState{state: "stopping", expectedStop: true}
	s.failProcess(st, "late RPC timeout", false)
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.state != "stopping" || !st.expectedStop || st.lastError != "" {
		t.Fatal("Поздняя проверка состояния отменила намеренную остановку")
	}
}

// Существующая фикстура проверяет настоящий супервизор Go, живой JAR Java, токен
// RPC и независимые проверки здоровья. При сбое JVM статус должен сохранять
// ошибку RPC, а не платформенный текст kill/signal.
func TestSupervisorPreservesJvmHangCause03012(t *testing.T) {
	host, install, key := javaHostFixture0304(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := host.StartInstallation(ctx, install); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		go func() {
			_, _ = host.CallJavaRPC0304(ctx, key, "command.invoke", []byte(`{"command":"hang","payload":{}}`))
		}()
	}
	deadline := time.NewTimer(19 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		status, err := host.Get(key)
		if err != nil {
			t.Fatal(err)
		}
		if status.State == "crashed" || status.State == "crashloop" {
			if !strings.Contains(status.LastError, "Java RPC не отвечает после трёх проверок") {
				t.Fatalf("Отсутствует исходная причина отказа: состояние=%s, ошибка=%q", status.State, status.LastError)
			}
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatalf("Зависший процесс Java не завершился: %+v", status)
		}
	}
}
