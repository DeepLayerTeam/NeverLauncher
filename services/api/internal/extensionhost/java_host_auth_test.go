package extensionhost

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestJavaAuthRPCMethodWhitelist0485(t *testing.T) {
	s := &Supervisor{}
	for _, method := range []string{"auth.health", "auth.password", "auth.resolve", "auth.session.verify", "auth.session.revoke"} {
		_, err := s.CallJavaRPC0304(context.Background(), Key{ExtensionID: "missing.identity", Scope: "global"}, method, json.RawMessage(`{}`))
		if err == nil || !strings.Contains(err.Error(), "not running") {
			t.Errorf("Ожидался отказ для отсутствующего хоста %s: %v", method, err)
		}
	}
	for _, method := range []string{"auth.session.issue", "auth.minecraft.entitlement", "auth.token.mint", "unsafe.eval"} {
		_, err := s.CallJavaRPC0304(context.Background(), Key{}, method, json.RawMessage(`{}`))
		if err == nil || !strings.Contains(err.Error(), "unsupported Java RPC method") {
			t.Errorf("Неожиданно разрешён метод %s: %v", method, err)
		}
	}
}
