package extensionhost

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIsolationDiagnosisCannotConflateKernelFeaturesWithEnforcement0311(t *testing.T) {
	d := DiagnoseIsolation0311()
	if d.Enforced || d.IsolationStatus != "unsupported" || d.Platform == "" {
		t.Fatalf("Непроверенная изолированная среда: %+v", d)
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "extension-os-sandbox-not-enforced") || !strings.Contains(string(b), `"enforced":false`) {
		t.Fatalf("Некорректная сериализация: %s", b)
	}
	// Проба никогда не запрашивает секреты пользователя и не меняет ограничения
	// хоста.
}
