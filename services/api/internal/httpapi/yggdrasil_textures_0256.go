package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/yggdrasiltexture"
)

// The authlib-injector key is NOT a ServerBridge or release manifest key.
// Loaded once per process to maintain stable public key/signatures for the life
// of the server (key rotation requires restart and coordinated metadata cache).
var yggdrasilSigners0256 sync.Map // file path -> *yggdrasiltexture.Signer

func (s Server) yggdrasilSigner0256() (*yggdrasiltexture.Signer, error) {
	path := strings.TrimSpace(s.Config.YggdrasilSigningKeyFile)
	if path == "" {
		if config.IsProductionEnvironment(s.Config.Environment) {
			return nil, errors.New("NEVERLAUNCHER_YGGDRASIL_RSA_KEY_FILE required in production")
		}
		return yggdrasiltexture.DevelopmentSigner()
	}
	if cached, ok := yggdrasilSigners0256.Load(path); ok {
		return cached.(*yggdrasiltexture.Signer), nil
	}
	signer, err := yggdrasiltexture.LoadFile(path)
	if err != nil {
		return nil, err
	}
	actual, _ := yggdrasilSigners0256.LoadOrStore(path, signer)
	return actual.(*yggdrasiltexture.Signer), nil
}

func validDomainRule0256(domain string) bool {
	if domain == "" || strings.ContainsAny(domain, "*/\\:@?#[] \t\r\n") {
		return false
	}
	if strings.HasPrefix(domain, ".") {
		domain = domain[1:]
		if domain == "" {
			return false
		}
	}
	if len(domain) > 253 || net.ParseIP(domain) != nil {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}
func (s Server) textureDomains0256() ([]string, error) {
	u, err := url.Parse(s.Config.PublicURL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid public texture origin")
	}
	host := strings.ToLower(u.Hostname())
	if u.Path != "" && u.Path != "/" {
		return nil, errors.New("public URL must be API origin without path")
	}
	if u.Scheme != "https" && (config.IsProductionEnvironment(s.Config.Environment) || u.Scheme != "http") {
		return nil, errors.New("texture origin must use HTTPS")
	}
	domains := []string{host}
	seen := map[string]bool{host: true}
	for _, raw := range s.Config.YggdrasilTextureDomains {
		rule := strings.ToLower(strings.TrimSpace(raw))
		if !validDomainRule0256(rule) {
			return nil, fmt.Errorf("invalid texture allowlist rule %q", raw)
		}
		if !seen[rule] {
			seen[rule] = true
			domains = append(domains, rule)
		}
	}
	return domains, nil
}
func domainAllowed0256(host string, domains []string) bool {
	host = strings.ToLower(host)
	for _, d := range domains {
		if host == d || strings.HasPrefix(d, ".") && strings.HasSuffix(host, d) {
			return true
		}
	}
	return false
}
func textureURLAllowed0256(raw string, domains []string, production bool) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Opaque != "" {
		return false
	}
	if u.Scheme != "https" && (production || u.Scheme != "http") {
		return false
	}
	// Only normalized content-addressed PNGs are suitable for signed properties.
	// Legacy arbitrary URLs must be imported by the bounded fetcher first.
	const prefix = "/api/v1/textures/blob/"
	if !strings.HasPrefix(u.Path, prefix) {
		return false
	}
	digest := strings.TrimPrefix(u.Path, prefix)
	if len(digest) != 64 {
		return false
	}
	for _, c := range digest {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return domainAllowed0256(u.Hostname(), domains)
}

func (s Server) textureProperty0256(texture bridgeTextureRecord, signed bool) (map[string]string, error) {
	signer, err := s.yggdrasilSigner0256()
	if err != nil {
		return nil, err
	}
	domains, err := s.textureDomains0256()
	if err != nil {
		return nil, err
	}
	production := config.IsProductionEnvironment(s.Config.Environment)
	// Never vouch for arbitrary legacy external URLs that bypassed PNG import.
	if !textureURLAllowed0256(texture.SkinURL, domains, production) {
		texture.SkinURL = ""
	}
	if !textureURLAllowed0256(texture.CapeURL, domains, production) {
		texture.CapeURL = ""
	}
	payload := textureProfile910(texture)
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	value := base64.StdEncoding.EncodeToString(encoded)
	property := map[string]string{"name": "textures", "value": value}
	if signed {
		signature, err := signer.SignValue(value)
		if err != nil {
			return nil, err
		}
		property["signature"] = signature
	}
	return property, nil
}
