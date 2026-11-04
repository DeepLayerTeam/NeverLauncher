package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func fixture02512(t *testing.T) (*httptest.Server, string, func()) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	pngImage := image.NewRGBA(image.Rect(0, 0, 64, 64))
	pngImage.Set(0, 0, color.RGBA{R: 77, G: 15, B: 88, A: 255})
	var data bytes.Buffer
	if err := png.Encode(&data, pngImage); err != nil {
		t.Fatal(err)
	}
	blob := data.Bytes()
	digest := sha256.Sum256(blob)
	hash := hex.EncodeToString(digest[:])
	uuid := "123456781234423492340123456789ab"
	var handler func(http.ResponseWriter, *http.Request)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler(w, r) }))
	handler = func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_ = json.NewEncoder(w).Encode(map[string]any{"skinDomains": []string{"127.0.0.1"}, "signaturePublickey": pemKey})
		case "/sessionserver/session/minecraft/profile/" + uuid:
			if r.URL.Query().Get("unsigned") != "false" {
				t.Errorf("requested unsigned payload")
			}
			signed := map[string]any{"profileId": uuid, "profileName": "Tester", "textures": map[string]any{"SKIN": map[string]string{"url": server.URL + "/api/v1/textures/blob/" + hash}}}
			payload, _ := json.Marshal(signed)
			encoded := base64.StdEncoding.EncodeToString(payload)
			sum := sha1.Sum([]byte(encoded))
			signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, sum[:])
			if err != nil {
				t.Error(err)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": uuid, "name": "Tester", "properties": []map[string]string{{"name": "textures", "value": encoded, "signature": base64.StdEncoding.EncodeToString(signature)}}})
		case "/api/v1/textures/blob/" + hash:
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(blob)
		default:
			http.NotFound(w, r)
		}
	}
	return server, uuid, func() { server.Close() }
}
func TestLiveYggdrasilProfileAndActualTexture02512(t *testing.T) {
	server, id, cleanup := fixture02512(t)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg := options02512{Origin: server.URL, UUID: id, ExpectSkin: true, AllowLoopbackHTTP: true}
	result, err := certify02512(ctx, server.Client(), cfg)
	if err != nil || result.Status != "passed" || !result.SignatureValid || !result.SkinChecked {
		t.Fatalf("signed profile and actual PNG: %+v %v", result, err)
	}
	cfg.ExpectCape = true
	if _, err := certify02512(ctx, server.Client(), cfg); err == nil {
		t.Fatal("absent required cape accepted")
	}
	cfg.ExpectCape = false
	cfg.AllowLoopbackHTTP = false
	if _, err := certify02512(ctx, server.Client(), cfg); err == nil {
		t.Fatal("non-TLS origin accepted")
	}
}
func TestCertProbeRejectsUnsafeURLs02512(t *testing.T) {
	for _, raw := range []string{"http://169.254.169.254/", "http://127.0.0.1.evil.test", "http://user:secret@127.0.0.1/", "file:///tmp/test", "https://example.com/api/path", "https://example.com/?x=1"} {
		if _, err := origin02512(raw, true); err == nil && strings.HasPrefix(raw, "http:") {
			t.Errorf("unsafe HTTP origin: %s", raw)
		}
	}
	for _, id := range []string{"evil", "../../../../../../../", strings.Repeat("a", 33)} {
		if _, err := cleanUUID02512(id); err == nil {
			t.Errorf("accepted bad UUID %q", id)
		}
	}
	if !domainAllowed02512("assets.example.test", []string{".example.test"}) || domainAllowed02512("example.test.evil.test", []string{"example.test"}) {
		t.Fatal("domain allowlist bypass")
	}
}
