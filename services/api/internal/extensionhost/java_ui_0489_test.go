package extensionhost

import (
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"testing"
)

func TestSignedJavaUI0489(t *testing.T) {
	signed := model.ExtensionManifest{
		Targets: []model.ExtensionTarget{{Kind: "backend"}, {Kind: "admin"}, {Kind: "desktop"}},
		Admin:   &model.ExtensionAdminContributions{Actions: []model.ExtensionAdminAction{{ID: "refresh"}}},
		Desktop: &model.ExtensionDesktopContributions{Actions: []model.ExtensionDesktopAction{{ID: "status"}}},
	}
	for _, test := range []struct {
		surface, method, action, key string
		expected                     bool
	}{
		{"admin", "ui.action.invoke", "refresh", "", true},
		{"desktop", "ui.action.invoke", "status", "", true},
		{"admin", "ui.action.invoke", "status", "", false},
		{"desktop", "ui.action.invoke", "refresh", "", false},
		{"admin", "ui.settings.get", "", "appearance", true},
		{"desktop", "ui.settings.put", "", "theme", true},
		{"desktop", "ui.settings.put", "", "../escape", false},
		{"backend", "ui.settings.get", "", "appearance", false},
		{"admin", "ui.settings.delete", "", "appearance", false},
	} {
		if got := javaUIContribution0489(signed, test.surface, test.method, test.action, test.key); got != test.expected {
			t.Errorf("%s %s %s %s: got %v", test.surface, test.method, test.action, test.key, got)
		}
	}
	signed.Targets = signed.Targets[1:]
	if javaUIContribution0489(signed, "admin", "ui.action.invoke", "refresh", "") {
		t.Fatal("UI callback without a running backend target accepted")
	}
}
