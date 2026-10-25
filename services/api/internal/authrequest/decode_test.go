package authrequest

import (
	"errors"
	"strings"
	"testing"
)

type login struct {
	ProviderID string `json:"providerId"`
	Password   string `json:"password"`
}

func TestDecodeRejectsAmbiguousOrUnboundedAuthRequests02912(t *testing.T) {
	for name, input := range map[string]string{
		"duplicate provider": `{"providerId":"strict","providerId":"local","password":"correct"}`,
		"case alias":         `{"providerId":"strict","ProviderId":"local","password":"correct"}`,
		"trailing object":    `{"password":"correct"}{"password":"wrong"}`,
		"not an object":      `[{"password":"correct"}]`,
		"unknown field":      `{"password":"correct","secret":"unused"}`,
		"malformed":          `{"password":`,
		"oversized":          `{"password":"` + strings.Repeat("x", MaxBytes) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var req login
			if err := Decode(strings.NewReader(input), &req); err == nil {
				t.Fatalf("ambiguous input accepted: %s", name)
			}
		})
	}
	var req login
	if err := Decode(strings.NewReader(`{"providerId":"strict","password":"correct"}`), &req); err != nil || req.ProviderID != "strict" || req.Password != "correct" {
		t.Fatalf("valid request failed: %+v %v", req, err)
	}
	if err := Decode(strings.NewReader(strings.Repeat(" ", MaxBytes+1)), &req); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("large input not rejected specifically: %v", err)
	}
}

func TestDecodeRejectsNestedDuplicates02912(t *testing.T) {
	var dst struct {
		Settings map[string]any `json:"settings"`
	}
	if err := Decode(strings.NewReader(`{"settings":{"role":"admin","role":"player"}}`), &dst); err == nil {
		t.Fatal("nested duplicate accepted")
	}
}
