package httpapi

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
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
		t.Fatal("missing signed textures")
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
		t.Fatalf("bad minecraft profile %#v", payload)
	}
	if payload.Textures["SKIN"].Metadata["model"] != "slim" {
		t.Fatal("bad slim model")
	}
	if _, ok := payload.Textures["CAPE"]; ok {
		t.Fatal("untrusted foreign cape URL signed")
	}
	rec := httptest.NewRecorder()
	s.yggdrasilMetadata119(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != 200 {
		t.Fatalf("metadata status=%d, body=%s", rec.Code, rec.Body.String())
	}
	var meta struct {
		SkinDomains        []string `json:"skinDomains"`
		SignaturePublickey string   `json:"signaturePublickey"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	if len(meta.SkinDomains) != 2 || meta.SkinDomains[0] != "api.example.test" {
		t.Fatalf("unexpected allowlist: %v", meta.SkinDomains)
	}
	block, _ := pem.Decode([]byte(meta.SignaturePublickey))
	if block == nil {
		t.Fatal("bad PEM")
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
		t.Fatal("unsigned profile must omit signature")
	}
	raw, _ = base64.StdEncoding.DecodeString(p["value"])
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if _, has := payload.Textures["SKIN"].Metadata["model"]; has {
		t.Fatal("classic must use default model not classic")
	}
}
func TestYggdrasilPolicyFailsClosed0256(t *testing.T) {
	s := Server{Config: config.Config{Environment: "production", PublicURL: "https://api.example.test"}}
	rec := httptest.NewRecorder()
	s.yggdrasilMetadata119(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("production without RSA key returned %d", rec.Code)
	}
	s.Config.Environment = "dev"
	s.Config.YggdrasilTextureDomains = []string{"*"}
	if _, err := s.textureProperty0256(bridgeTextureRecord{UUID: "x", Username: "x"}, true); err == nil {
		t.Fatal("wildcard allowlist accepted")
	}
	for _, tc := range []string{"http://127.0.0.1/private", "https://api.example.test@evil.test/x", "https://api.example.test.evil.test/x"} {
		if textureURLAllowed0256(tc, []string{"api.example.test"}, true) {
			t.Errorf("unsafe URL allowed: %q", tc)
		}
	}
	if !domainAllowed0256("cdn.example.test", []string{".example.test"}) || domainAllowed0256("example.test", []string{".example.test"}) {
		t.Fatal("suffix matching broken")
	}
}

func TestYggdrasilProtocolWriteRejectsMissingMinecraftBearer0256(t *testing.T) {
	handler := testServer(t)
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		request := httptest.NewRequest(method, "/api/user/profile/123456781234423492340123456789ab/skin", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("%s unauthenticated write accepted: %d", method, response.Code)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/api/profiles/minecraft", strings.NewReader(`{"name":"not-an-array"}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid batch accepted: %d", response.Code)
	}
}
