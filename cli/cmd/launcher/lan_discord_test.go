package main

import (
	"strings"
	"testing"
)

func TestLAN0308RejectUnpinnedVerify(t *testing.T) {
	err := handleLAN0308([]string{"verify", "--url", "https://192.0.2.25:8443"})
	if err == nil || !strings.Contains(err.Error(), "--pin") {
		t.Fatalf("ожидалась ошибка обязательного закрепления ключа, получено: %v", err)
	}
}
func TestLAN0308RejectNonLocalAdvertiser(t *testing.T) {
	err := handleLAN0308([]string{"publish", "--instance", "Sample", "--url", "https://192.0.2.25:8443", "--fingerprint", strings.Repeat("a", 64)})
	if err == nil || !strings.Contains(err.Error(), "локальному интерфейсу LAN") {
		t.Fatalf("ожидалась проверка локального IP-адреса, получено: %v", err)
	}
}
func TestLAN0308RejectInvalidArguments(t *testing.T) {
	if err := handleLAN0308([]string{"discover", "--timeout", "45s"}); err == nil {
		t.Fatal("принята слишком большая длительность обнаружения")
	}
	if err := handleLAN0308([]string{"unknown"}); err == nil {
		t.Fatal("неизвестная команда была принята")
	}
}
func TestDiscord0308RejectInvalidIDBeforeConnecting(t *testing.T) {
	err := handleDiscord0308([]string{"presence", "--application-id", "not-a-snowflake"})
	if err == nil || !strings.Contains(err.Error(), "snowflake") {
		t.Fatalf("ожидалась ошибка недопустимого идентификатора приложения, получено: %v", err)
	}
}
