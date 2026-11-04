package extensioncontract

import "testing"

func TestCanonicalAPIVersion(t *testing.T) {
	for _, value := range []string{"1.0", "1.0.0", "v1", "3.7", "3.7.0"} {
		got, err := CanonicalAPIVersion(value)
		if err != nil || got != ExtensionAPIVersion {
			t.Fatalf("CanonicalAPIVersion(%q) = %q, %v", value, got, err)
		}
	}
	if _, err := CanonicalAPIVersion("2.0"); err == nil {
		t.Fatal("unsupported API must fail")
	}
}
func TestHostHelloCompatibility(t *testing.T) {
	if !SupportsHostHello("3.7", "") {
		t.Fatal("legacy 0.20 hello must remain compatible")
	}
	if !SupportsHostHello("3.7", "1.0") {
		t.Fatal("legacy manifest with GA SDK must work")
	}
	if !SupportsHostHello("1.0", "1.0") {
		t.Fatal("GA hello must work")
	}
	if SupportsHostHello("1.0", "") {
		t.Fatal("GA manifest must require API version in hello")
	}
}
func TestRequireGA(t *testing.T) {
	if err := RequireGAAPIVersion("1.0"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"3.7", "1.0.0", "v1", "v1.0"} {
		if err := RequireGAAPIVersion(value); err == nil {
			t.Fatalf("non-canonical API %q must not be accepted for new GA publication", value)
		}
	}
}
