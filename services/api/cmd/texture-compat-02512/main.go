// texture-compat-02512 verifies a running local Yggdrasil/authlib-injector
// deployment, not a mock contract. It retrieves, verifies and decodes real
// signed profile and content-addressed texture bytes from the configured API.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/texturepng"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const maxResponse02512 = 4 << 20

type options02512 struct {
	Origin, UUID                              string
	ExpectSkin, ExpectCape, AllowLoopbackHTTP bool
}
type report02512 struct {
	Status         string `json:"status"`
	ProfileID      string `json:"profileId"`
	SignatureValid bool   `json:"signatureValid"`
	SkinChecked    bool   `json:"skinChecked"`
	CapeChecked    bool   `json:"capeChecked"`
}

type metadata02512 struct {
	SkinDomains        []string `json:"skinDomains"`
	SignaturePublicKey string   `json:"signaturePublickey"`
}
type property02512 struct{ Name, Value, Signature string }
type profile02512 struct {
	ID, Name   string
	Properties []property02512
}
type textureEntry02512 struct {
	URL      string `json:"url"`
	Metadata struct {
		Model string `json:"model"`
	} `json:"metadata"`
}
type payload02512 struct {
	ProfileID, ProfileName string
	Textures               map[string]textureEntry02512
}

func main() {
	var opt options02512
	flag.StringVar(&opt.Origin, "origin", "", "HTTPS API origin (no path)")
	flag.StringVar(&opt.UUID, "uuid", "", "local Minecraft profile UUID")
	flag.BoolVar(&opt.ExpectSkin, "expect-skin", true, "require an active managed skin")
	flag.BoolVar(&opt.ExpectCape, "expect-cape", false, "require an active managed cape")
	flag.BoolVar(&opt.AllowLoopbackHTTP, "allow-loopback-http", false, "permit http://127.0.0.1 for local disposable integration tests")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	result, err := certify02512(ctx, client, opt)
	if err != nil {
		fmt.Fprintln(os.Stderr, "texture compatibility FAILED:", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func cleanUUID02512(id string) (string, error) {
	id = strings.ToLower(strings.ReplaceAll(id, "-", ""))
	if len(id) != 32 {
		return "", errors.New("Minecraft UUID must contain 32 hex digits")
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", errors.New("invalid Minecraft UUID")
		}
	}
	return id, nil
}
func origin02512(raw string, allowLoopback bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Opaque != "" {
		return nil, errors.New("origin must be an HTTP(S) origin without path, credentials or query")
	}
	if u.Scheme == "https" {
		return u, nil
	}
	if u.Scheme != "http" || !allowLoopback || !isLoopback02512(u.Hostname()) {
		return nil, errors.New("HTTPS required; HTTP permitted only for explicit loopback test")
	}
	return u, nil
}
func isLoopback02512(host string) bool { ip := net.ParseIP(host); return ip != nil && ip.IsLoopback() }
func fetch02512(ctx context.Context, c *http.Client, raw string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET %s HTTP %d", req.URL.Path, resp.StatusCode)
	}
	if resp.ContentLength > maxResponse02512 {
		return nil, errors.New("oversized profile or texture response")
	}
	content, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse02512+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maxResponse02512 {
		return nil, errors.New("oversized profile or texture response")
	}
	return content, nil
}
func domainAllowed02512(host string, domains []string) bool {
	host = strings.ToLower(host)
	for _, domain := range domains {
		domain = strings.ToLower(domain)
		if domain == host || strings.HasPrefix(domain, ".") && strings.HasSuffix(host, domain) && len(host) > len(domain) {
			return true
		}
	}
	return false
}
func checkTexture02512(ctx context.Context, c *http.Client, raw string, kind, model string, meta metadata02512, origin *url.URL, loopback bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Scheme != origin.Scheme && !(u.Scheme == "https" && origin.Scheme == "http") {
		return errors.New("invalid texture URL")
	}
	if u.Scheme != "https" && !(loopback && u.Scheme == "http" && isLoopback02512(u.Hostname())) {
		return errors.New("insecure texture URL")
	}
	if !domainAllowed02512(u.Hostname(), meta.SkinDomains) {
		return errors.New("texture host not in authlib-injector allowlist")
	}
	if strings.ToLower(u.Hostname()) != strings.ToLower(origin.Hostname()) {
		return errors.New("texture host differs from verified API origin; external fetch disallowed by probe")
	}
	if u.Port() != origin.Port() {
		return errors.New("texture port differs from API origin")
	}
	const prefix = "/api/v1/textures/blob/"
	if !strings.HasPrefix(u.Path, prefix) {
		return errors.New("texture is not a managed blob")
	}
	digest := strings.TrimPrefix(u.Path, prefix)
	if len(digest) != 64 {
		return errors.New("invalid content-addressed digest")
	}
	if _, err := hex.DecodeString(digest); err != nil || strings.ToLower(digest) != digest {
		return errors.New("invalid lowercase digest")
	}
	content, err := fetch02512(ctx, c, u.String())
	if err != nil {
		return err
	}
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != digest {
		return errors.New("texture SHA-256 does not match public URL")
	}
	// Use the same full parser and geometry restrictions as production uploads:
	// CRCs, animation, trailing bytes, pixel limits and actual decompression.
	if _, err := texturepng.Process(bytes.NewReader(content), kind, model); err != nil {
		return fmt.Errorf("invalid managed %s PNG: %w", kind, err)
	}
	return nil
}
func certify02512(ctx context.Context, client *http.Client, opt options02512) (report02512, error) {
	report := report02512{Status: "failed"}
	uid, err := cleanUUID02512(opt.UUID)
	if err != nil {
		return report, err
	}
	origin, err := origin02512(opt.Origin, opt.AllowLoopbackHTTP)
	if err != nil {
		return report, err
	}
	metadataRaw, err := fetch02512(ctx, client, origin.String()+"/")
	if err != nil {
		return report, fmt.Errorf("Yggdrasil metadata: %w", err)
	}
	var metadata metadata02512
	if err := json.Unmarshal(metadataRaw, &metadata); err != nil {
		return report, err
	}
	if !domainAllowed02512(origin.Hostname(), metadata.SkinDomains) {
		return report, errors.New("metadata does not allow the API origin")
	}
	block, _ := pem.Decode([]byte(metadata.SignaturePublicKey))
	if block == nil {
		return report, errors.New("metadata missing PEM public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return report, err
	}
	key, ok := pub.(*rsa.PublicKey)
	if !ok || key.N.BitLen() < 2048 {
		return report, errors.New("authlib-injector signing key must be RSA >= 2048 bits")
	}
	raw, err := fetch02512(ctx, client, origin.String()+"/sessionserver/session/minecraft/profile/"+uid+"?unsigned=false")
	if err != nil {
		return report, err
	}
	var profile profile02512
	if err := json.Unmarshal(raw, &profile); err != nil {
		return report, err
	}
	if profile.ID != uid || profile.Name == "" {
		return report, errors.New("profile identity mismatch")
	}
	if len(profile.Properties) != 1 || profile.Properties[0].Name != "textures" || profile.Properties[0].Signature == "" {
		return report, errors.New("profile lacks exactly one signed textures property")
	}
	prop := profile.Properties[0]
	digest := sha1.Sum([]byte(prop.Value))
	sig, err := base64.StdEncoding.DecodeString(prop.Signature)
	if err != nil {
		return report, err
	}
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA1, digest[:], sig); err != nil {
		return report, fmt.Errorf("RSA texture signature invalid: %w", err)
	}
	report.SignatureValid = true
	report.ProfileID = uid
	payloadBytes, err := base64.StdEncoding.DecodeString(prop.Value)
	if err != nil {
		return report, err
	}
	var payload payload02512
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return report, err
	}
	if payload.ProfileID != uid || payload.ProfileName != profile.Name {
		return report, errors.New("signed texture property identity mismatch")
	}
	for _, kind := range []string{"SKIN", "CAPE"} {
		entry, found := payload.Textures[kind]
		required := kind == "SKIN" && opt.ExpectSkin || kind == "CAPE" && opt.ExpectCape
		if !found {
			if required {
				return report, fmt.Errorf("active %s texture missing", kind)
			}
			continue
		}
		if kind == "SKIN" && entry.Metadata.Model != "" && entry.Metadata.Model != "slim" {
			return report, errors.New("Minecraft skin model must be default or slim")
		}
		model := "classic"
		if entry.Metadata.Model == "slim" {
			model = "slim"
		}
		if err := checkTexture02512(ctx, client, entry.URL, strings.ToLower(kind), model, metadata, origin, opt.AllowLoopbackHTTP); err != nil {
			return report, fmt.Errorf("%s: %w", kind, err)
		}
		if kind == "SKIN" {
			report.SkinChecked = true
		} else {
			report.CapeChecked = true
		}
	}
	report.Status = "passed"
	return report, nil
}
