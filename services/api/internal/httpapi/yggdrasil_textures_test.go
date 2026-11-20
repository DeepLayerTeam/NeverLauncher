package httpapi

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
)

func TestSignedTextureProtocol0256(t *testing.T) {
	s := Server{Config: config.Config{Environment: "dev", PublicURL: "https://api.example.test", YggdrasilTextureDomains: []string{"assets.example.test"}}, Version: "0.25.6"}
	record := bridgeTextureRecord{UUID: "12345678-1234-4234-9234-0123456789ab", Username: "Example", SkinURL: "https://api.example.test/api/v1/textures/blob/" + strings.Repeat("a", 64), CapeURL: "https://evil.test/cape.png", Model: "slim"}
	p, err := s.textureProperty0256(record, true)
	if err != nil {
		t.Fatal(err)
	}
	if p["name"] != "textures" || p["signature"] == "" {
		t.Fatal("отсутствуют подписанные текстуры")
	}
	raw, err := base64.StdEncoding.DecodeString(p["value"])
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		ProfileID   string `json:"profileId"`
		ProfileName string `json:"profileName"`
		Textures    map[string]struct {
			URL      string            `json:"url"`
			Metadata map[string]string `json:"metadata"`
		} `json:"textures"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ProfileID != "123456781234423492340123456789ab" || payload.ProfileName != "Example" {
		t.Fatalf("некорректный профиль Minecraft: %#v", payload)
	}
	if payload.Textures["SKIN"].Metadata["model"] != "slim" {
		t.Fatal("неверная модель slim")
	}
	if _, ok := payload.Textures["CAPE"]; ok {
		t.Fatal("подписан недоверенный внешний URL плаща")
	}
	rec := httptest.NewRecorder()
	s.yggdrasilMetadata119(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != 200 {
		t.Fatalf("статус метаданных=%d, тело=%s", rec.Code, rec.Body.String())
	}
	var meta struct {
		SkinDomains        []string `json:"skinDomains"`
		SignaturePublickey string   `json:"signaturePublickey"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	if len(meta.SkinDomains) != 2 || meta.SkinDomains[0] != "api.example.test" {
		t.Fatalf("Неожиданный список разрешённых значений: %v", meta.SkinDomains)
	}
	block, _ := pem.Decode([]byte(meta.SignaturePublickey))
	if block == nil {
		t.Fatal("Некорректный PEM")
	}
	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha1.Sum([]byte(p["value"]))
	signature, err := base64.StdEncoding.DecodeString(p["signature"])
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(pk.(*rsa.PublicKey), crypto.SHA1, digest[:], signature); err != nil {
		t.Fatal(err)
	}
	record.Model = "classic"
	p, err = s.textureProperty0256(record, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, has := p["signature"]; has {
		t.Fatal("неподписанный профиль не должен содержать подпись")
	}
	raw, _ = base64.StdEncoding.DecodeString(p["value"])
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if _, has := payload.Textures["SKIN"].Metadata["model"]; has {
		t.Fatal("для classic должна использоваться модель по умолчанию, а не значение classic")
	}
}
func TestYggdrasilPolicyFailsClosed0256(t *testing.T) {
	s := Server{Config: config.Config{Environment: "production", PublicURL: "https://api.example.test"}}
	rec := httptest.NewRecorder()
	s.yggdrasilMetadata119(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("промышленная конфигурация без ключа RSA вернула %d", rec.Code)
	}
	s.Config.Environment = "dev"
	s.Config.YggdrasilTextureDomains = []string{"*"}
	if _, err := s.textureProperty0256(bridgeTextureRecord{UUID: "x", Username: "x"}, true); err == nil {
		t.Fatal("принят список разрешённых значений с подстановочными символами")
	}
	for _, tc := range []string{"http://127.0.0.1/private", "https://api.example.test@evil.test/x", "https://api.example.test.evil.test/x"} {
		if textureURLAllowed0256(tc, []string{"api.example.test"}, true) {
			t.Errorf("разрешён небезопасный URL: %q", tc)
		}
	}
	if !domainAllowed0256("cdn.example.test", []string{".example.test"}) || domainAllowed0256("example.test", []string{".example.test"}) {
		t.Fatal("сопоставление по суффиксу нарушено")
	}
}

// Для production подписанные HTTP URL запрещены; отдельный loopback E2E
// должен уметь подписывать настоящий профиль, как требует ValidateProduction.
func TestYggdrasilLoopbackE2EPolicy0256(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "localhost", "[::1]"} {
		s := Server{Config: config.Config{Environment: "e2e-production", PublicURL: "http://" + addr + ":18081"}}
		if _, err := s.textureDomains0256(); err != nil {
			t.Errorf("E2E loopback %s: %v", addr, err)
		}
	}
	for _, tc := range []struct{ environment, publicURL string }{
		{"production", "http://127.0.0.1:18081"},
		{"prod", "http://localhost:18081"},
		{"e2e-production", "http://example.test:18081"},
	} {
		s := Server{Config: config.Config{Environment: tc.environment, PublicURL: tc.publicURL}}
		if _, err := s.textureDomains0256(); err == nil {
			t.Errorf("небезопасный URL %s в %s принят", tc.publicURL, tc.environment)
		}
	}
}

func TestYggdrasilLoopbackE2ERealRSASigning0256(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "yggdrasil.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)})
	if err := os.WriteFile(keyFile, pemBytes, 0600); err != nil {
		t.Fatal(err)
	}
	s := Server{Config: config.Config{
		Environment: "e2e-production", PublicURL: "http://127.0.0.1:18081", YggdrasilSigningKeyFile: keyFile,
	}}
	skin := "http://127.0.0.1:18081/api/v1/textures/blob/" + strings.Repeat("a", 64)
	property, err := s.textureProperty0256(bridgeTextureRecord{
		UUID: "12345678-1234-4234-9234-0123456789ab", Username: "LocalPlayer", SkinURL: skin,
	}, true)
	if err != nil {
		t.Fatalf("В производственном E2E-профиле не удалось подписать текстуру: %v", err)
	}
	signature, err := base64.StdEncoding.DecodeString(property["signature"])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha1.Sum([]byte(property["value"]))
	if err := rsa.VerifyPKCS1v15(&private.PublicKey, crypto.SHA1, digest[:], signature); err != nil {
		t.Fatalf("Подпись RSA не прошла проверку: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(property["value"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(decoded), skin) {
		t.Fatalf("Локальная текстура E2E потеряна: %s", decoded)
	}
}

func TestYggdrasilProtocolWriteRejectsMissingMinecraftBearer0256(t *testing.T) {
	handler := testServer(t)
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		request := httptest.NewRequest(method, "/api/user/profile/123456781234423492340123456789ab/skin", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("%s: разрешена запись без аутентификации: %d", method, response.Code)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/api/profiles/minecraft", strings.NewReader(`{"name":"not-an-array"}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("принят недопустимый пакет: %d", response.Code)
	}
}
