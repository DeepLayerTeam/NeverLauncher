package serverbridgeha

import (
	"context"
	"testing"
	"time"
)

func TestRedisLeaseCannotAliasAnotherKey0514(t *testing.T) {
	fake := newFakeRedis01911(t)
	coord, err := NewRedis(fake.url())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	owner, token := "valid-channel-aaaaaaaaaaaaaaaa", "valid-token-aaaaaaaaaaaaaaaa"
	acquired, err := coord.AcquireCommandLease(ctx, "server-a", "command-one", owner, token, time.Minute)
	if err != nil || !acquired {
		t.Fatalf("Не удалось выполнить допустимый захват: %t, %v", acquired, err)
	}
	for _, invalid := range []string{"server/a", "server:a", "server a", "", "server|a", "сервер"} {
		if _, err := coord.AcquireCommandLease(ctx, invalid, "command-one", owner, token, time.Minute); err == nil {
			t.Errorf("Принят идентификатор сервера с потерей данных %q", invalid)
		}
		if _, err := coord.VerifyCommandLease(ctx, invalid, "command-one", owner, token); err == nil {
			t.Errorf("Проверен идентификатор сервера с потерей данных %q", invalid)
		}
		if err := coord.ReleaseCommandLease(ctx, invalid, "command-one", owner, token); err == nil {
			t.Errorf("Освобождён идентификатор сервера с потерей данных %q", invalid)
		}
	}
	ok, err := coord.VerifyCommandLease(ctx, "server-a", "command-one", owner, token)
	if err != nil || !ok {
		t.Fatalf("Некорректное освобождение затронуло действующую аренду: %t, %v", ok, err)
	}
}
