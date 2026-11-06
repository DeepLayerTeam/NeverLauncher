package extensionhost

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestJavaScratch04811(t *testing.T) {
	cmd := exec.Command("java", "-Xmx256m", "-jar", "module.jar", "status")
	cmd.Env = []string{"PATH=/bin", "HOME=/sensitive/home", "TMPDIR=/sensitive/tmp", "JDK_JAVA_OPTIONS=-Xmx5000m"}
	scratch, err := prepareJavaScratch04811(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(scratch)
	info, err := os.Stat(scratch)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("режим временного каталога: %v, %v", info, err)
	}
	if cmd.Args[len(cmd.Args)-2] != "module.jar" || cmd.Args[len(cmd.Args)-1] != "status" {
		t.Fatalf("аргументы JAR были изменены: %v", cmd.Args)
	}
	joined := strings.Join(cmd.Args, " ")
	if !strings.Contains(joined, "-Duser.home="+filepath.Join(scratch, "home")) ||
		!strings.Contains(joined, "-Djava.io.tmpdir="+filepath.Join(scratch, "tmp")) {
		t.Fatalf("отсутствуют приватные каталоги Runtime Java: %s", joined)
	}
	for _, entry := range cmd.Env {
		if strings.HasPrefix(entry, "HOME=/sensitive") || strings.HasPrefix(entry, "TMPDIR=/sensitive") {
			t.Fatalf("унаследован приватный каталог: %s", entry)
		}
	}
	if _, err := prepareJavaScratch04811(exec.Command("java", "-version")); err == nil {
		t.Fatal("принята команда без JAR")
	}
}

func TestJavaResourceLimits04811(t *testing.T) {
	s := &Supervisor{cfg: Config{MaxMemoryBytes: 512 << 20}.normalized()}
	cmd, err := s.javaCommand0304("module.jar", nil)
	if err != nil {
		t.Skipf("Среда выполнения Java недоступна: %v", err)
	}
	args := strings.Join(cmd.Args, " ")
	for _, flag := range []string{"-Xmx204m", "-XX:MaxMetaspaceSize=102m", "-XX:MaxDirectMemorySize=51m", "-XX:ReservedCodeCacheSize=51m", "-XX:+DisableAttachMechanism", "-XX:-CreateCoredumpOnCrash"} {
		if !strings.Contains(args, flag) {
			t.Errorf("Отсутствует ограничение JVM %s: %s", flag, args)
		}
	}
	s.cfg.MaxMemoryBytes = 64 << 20
	if _, err := s.javaCommand0304("module.jar", nil); err == nil {
		t.Fatal("принят объём памяти JVM ниже безопасного минимума")
	}
}

func TestJavaRawSecretDenied04811(t *testing.T) {
	s := &Supervisor{}
	st := &processState{javaHost: true}
	result := s.executeCapability(context.Background(), st, "secret.get", capabilityRequest{Name: "db_password"})
	if result.status != http.StatusForbidden {
		t.Fatalf("допущена передача открытого секрета Java: %d", result.status)
	}
}

func TestJavaTokenRedaction04811(t *testing.T) {
	token := strings.Repeat("a", 64)
	callback := strings.Repeat("b", 64)
	st := &processState{token: token, callbackToken: callback, logs: ringLog{maxBytes: 4096, maxEntries: 10}}
	s := &Supervisor{}
	s.addLog(st, "stdout", "info", "Bearer "+token+" callback="+callback,
		map[string]any{"accessToken": token, "metadata": map[string]any{"Authorization": callback, "note": token}})
	lines := st.logs.list(10)
	if len(lines) != 1 {
		t.Fatalf("ожидался журнал с замаскированными секретами: %+v", lines)
	}
	if strings.Contains(lines[0].Message, token) || strings.Contains(lines[0].Message, callback) {
		t.Fatal("токен раскрыт в сохранённом журнале")
	}
	if strings.Contains(lines[0].Fields["metadata"].(map[string]any)["note"].(string), token) {
		t.Fatal("вложенный токен раскрыт")
	}
	if got := redactHostCredentials04811("unchanged", ""); got != "unchanged" {
		t.Fatalf("пустой токен изменил журнал: %s", got)
	}
}

func TestJavaHostIPCQuota04811(t *testing.T) {
	token := strings.Repeat("c", 64)
	st := &processState{token: token, javaHost: true}
	s := &Supervisor{tokens: map[string]*processState{token: st}}
	calls := 0
	handler := s.limitedHostHandler03113(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(http.StatusOK) }))
	for i := 0; i < defaultRequestsPerSecond03113+1; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if i == defaultRequestsPerSecond03113 && w.Code != http.StatusTooManyRequests {
			t.Fatalf("Не применяется квота хоста Java: %d", w.Code)
		}
	}
	if calls != defaultRequestsPerSecond03113 {
		t.Fatalf("запросы достигли хоста после превышения лимита: %d", calls)
	}
}
