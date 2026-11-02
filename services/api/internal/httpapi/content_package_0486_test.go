package httpapi

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestJavaContentTransformVerification0486(t *testing.T) {
	payload := []byte("real-data-transformed")
	sum := sha256.Sum256(payload)
	base := preparedJavaContent0486{DataBase64: base64.StdEncoding.EncodeToString(payload), SHA256: hex.EncodeToString(sum[:]), Size: len(payload), RequiresSigning: true}
	toJSON := func(v preparedJavaContent0486) json.RawMessage {
		t.Helper()
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	got, err := decodeJavaPreparedContent0486(toJSON(base))
	if err != nil || string(got) != string(payload) {
		t.Fatalf("valid prepared content rejected: %v", err)
	}
	for _, bad := range []preparedJavaContent0486{
		{DataBase64: base.DataBase64, SHA256: base.SHA256, Size: base.Size, RequiresSigning: false},
		{DataBase64: base.DataBase64, SHA256: "0", Size: base.Size, RequiresSigning: true},
		{DataBase64: base.DataBase64, SHA256: base.SHA256, Size: base.Size + 1, RequiresSigning: true},
		{DataBase64: "bad***", SHA256: base.SHA256, Size: base.Size, RequiresSigning: true},
		{ErrorCode: "content_denied"},
		{DataBase64: base.DataBase64, SHA256: base.SHA256, Size: 100000, RequiresSigning: true},
	} {
		if _, e := decodeJavaPreparedContent0486(toJSON(bad)); e == nil {
			t.Fatalf("invalid Java transform accepted: %+v", bad)
		}
	}
}
