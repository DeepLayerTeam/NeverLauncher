package extensioncontract

import "testing"

func TestCanonicalAPIVersion(t *testing.T) {
	for _, value := range []string{"1.0", "1.0.0", "v1", "3.7", "3.7.0"} {
		got, err := CanonicalAPIVersion(value)
		if err != nil || got != ExtensionAPIVersion {
			t.Fatalf("проверка CanonicalAPIVersion(%q): получено %q, ошибка %v", value, got, err)
		}
	}
	if _, err := CanonicalAPIVersion("2.0"); err == nil {
		t.Fatal("Неподдерживаемая версия API должна приводить к ошибке")
	}
}
func TestHostHelloCompatibility(t *testing.T) {
	if !SupportsHostHello("3.7", "") {
		t.Fatal("Приветственное сообщение версии 0.20 должно сохранять совместимость")
	}
	if !SupportsHostHello("3.7", "1.0") {
		t.Fatal("Старый манифест должен работать с GA SDK")
	}
	if !SupportsHostHello("1.0", "1.0") {
		t.Fatal("Приветственное сообщение GA должно работать")
	}
	if SupportsHostHello("1.0", "") {
		t.Fatal("Манифест GA должен требовать версию API в приветственном сообщении")
	}
}
func TestRequireGA(t *testing.T) {
	if err := RequireGAAPIVersion("1.0"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"3.7", "1.0.0", "v1", "v1.0"} {
		if err := RequireGAAPIVersion(value); err == nil {
			t.Fatalf("Неканоническая версия API %q не должна приниматься при новой публикации GA", value)
		}
	}
}
