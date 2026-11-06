package sqlitepg

import (
	"context"
	"testing"
)

func TestBackendGate0475RequiresDatabase(t *testing.T) {
	if err := RejectUnapprovedBackend0475(context.Background(), ""); err == nil {
		t.Fatal("принята пустая строка подключения DSN: проверка не запретила доступ при ошибке")
	}
}
