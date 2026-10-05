package main

import (
	"strings"
	"testing"
)

func TestExtensionSecurityCLI0207RoutesThroughExtensionCommand(t *testing.T) {
	for _, command := range []string{"capabilities", "permissions", "permission-grant", "permission-revoke", "secrets", "secret-set", "secret-delete"} {
		err := handleExtension0201([]string{command})
		if err == nil || !strings.Contains(err.Error(), "--backend") {
			t.Fatalf("%s was not routed to extension security handler: %v", command, err)
		}
	}
}

func TestExtensionSecurityCLI0207SecretInputFlag(t *testing.T) {
	if !hasFlag0207([]string{"example.ext", "--stdin"}, "--stdin") {
		t.Fatal("--stdin flag not detected")
	}
	if hasFlag0207([]string{"example.ext"}, "--stdin") {
		t.Fatal("--stdin reported when absent")
	}
}
