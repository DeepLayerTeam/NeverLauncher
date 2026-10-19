package httpapi

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"os"
	"strings"
	"time"
)

// The control plane uses the same role-separated, root-signed policy bytes as
// Prestarter and NeverRuntime. An API request may NOT supply its own trust root.
type gameTrustEnvelope02312 struct {
	SchemaVersion string `json:"schemaVersion"`
	Payload       string `json:"payload"`
	RootSignature string `json:"rootSignature"`
}
type gameTrustKey02312 struct {
	ID          string `json:"id"`
	Role        string `json:"role"`
	PublicKey   string `json:"publicKey"`
	Status      string `json:"status"`
	NotBefore   string `json:"notBefore"`
	VerifyUntil string `json:"verifyUntil"`
}
type gameTrustPolicy02312 struct {
	SchemaVersion string              `json:"schemaVersion"`
	Domain        string              `json:"domain"`
	Epoch         uint64              `json:"epoch"`
	IssuedAt      string              `json:"issuedAt"`
	ExpiresAt     string              `json:"expiresAt"`
	Keys          []gameTrustKey02312 `json:"keys"`
}

func gameTrustUTC02312(s string) (time.Time, error) { return time.Parse("2006-01-02T15:04:05Z", s) }
func currentGameTrust02312() (gameTrustPolicy02312, error) {
	var p gameTrustPolicy02312
	rootHex := strings.TrimSpace(os.Getenv("NEVERLAUNCHER_GAME_TRUST_ROOT_PUBLIC_KEY"))
	path := strings.TrimSpace(os.Getenv("NEVERLAUNCHER_GAME_TRUST_POLICY_FILE"))
	if rootHex == "" || path == "" {
		return p, errors.New("trusted game policy path and provisioned root key required for production signing")
	}
	root, e := hex.DecodeString(rootHex)
	if e != nil || len(root) != 32 {
		return p, errors.New("invalid game trust root")
	}
	stat, e := os.Lstat(path)
	if e != nil {
		return p, e
	}
	if !stat.Mode().IsRegular() || stat.Size() > 128*1024 {
		return p, errors.New("unsafe game policy file")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return p, e
	}
	var env gameTrustEnvelope02312
	if e = json.Unmarshal(raw, &env); e != nil {
		return p, e
	}
	if env.SchemaVersion != "1.0" {
		return p, errors.New("unsupported game policy envelope")
	}
	payload, e := base64.StdEncoding.Strict().DecodeString(env.Payload)
	if e != nil || len(payload) > 96*1024 {
		return p, errors.New("invalid game trust policy payload")
	}
	sig, e := hex.DecodeString(env.RootSignature)
	if e != nil || len(sig) != 64 || !ed25519.Verify(ed25519.PublicKey(root), append([]byte("NeverLauncher-Trust-Policy-v1\n"), payload...), sig) {
		return p, errors.New("game trust root signature invalid")
	}
	if e = json.Unmarshal(payload, &p); e != nil {
		return p, e
	}
	if p.SchemaVersion != "1.0" || p.Domain != "neverlauncher.trust.v1" || p.Epoch == 0 {
		return p, errors.New("invalid game trust domain/epoch")
	}
	start, e := gameTrustUTC02312(p.IssuedAt)
	if e != nil {
		return p, e
	}
	end, e := gameTrustUTC02312(p.ExpiresAt)
	if e != nil {
		return p, e
	}
	now := time.Now().UTC()
	if start.After(now.Add(5*time.Minute)) || !end.After(now) || end.Sub(start) > 90*24*time.Hour {
		return p, errors.New("expired/future game trust policy")
	}
	return p, nil
}
func authorizedGameSigningKey02312(policy gameTrustPolicy02312, pub string, signedAt time.Time, issuance bool) error {
	for _, k := range policy.Keys {
		if k.Role != "game" || !strings.EqualFold(k.PublicKey, pub) {
			continue
		}
		if k.Status == "revoked" {
			return errors.New("revoked game signing key")
		}
		if k.Status != "active" && k.Status != "verify-only" {
			return errors.New("unknown game signing key status")
		}
		if issuance && k.Status != "active" {
			return errors.New("retired game signing key cannot publish")
		}
		first, e := gameTrustUTC02312(k.NotBefore)
		if e != nil {
			return e
		}
		if signedAt.Before(first) || signedAt.After(time.Now().UTC().Add(5*time.Minute)) {
			return errors.New("game signature timestamp outside key window")
		}
		if k.Status == "verify-only" {
			limit, e := gameTrustUTC02312(k.VerifyUntil)
			if e != nil {
				return e
			}
			if !time.Now().UTC().Before(limit) || !signedAt.Before(limit) {
				return errors.New("game verify-only overlap expired")
			}
		}
		return nil
	}
	return fmt.Errorf("game signing key not delegated by root: %s", pub)
}
func (s Server) enforceGameTrustSigning02312(manifest *model.Manifest, private ed25519.PrivateKey) error {
	configured := os.Getenv("NEVERLAUNCHER_GAME_TRUST_POLICY_FILE") != "" || os.Getenv("NEVERLAUNCHER_GAME_TRUST_ROOT_PUBLIC_KEY") != ""
	production := strings.EqualFold(s.Config.Environment, "production") || strings.EqualFold(s.Config.Environment, "prod")
	if !configured && !production {
		return nil
	}
	p, e := currentGameTrust02312()
	if e != nil {
		return e
	}
	key := hex.EncodeToString(private.Public().(ed25519.PublicKey))
	if e = authorizedGameSigningKey02312(p, key, time.Now().UTC(), true); e != nil {
		return e
	}
	manifest.TrustEpoch = p.Epoch
	return nil
}
func (s Server) enforceGameTrustVerify02312(manifest model.Manifest) error {
	configured := os.Getenv("NEVERLAUNCHER_GAME_TRUST_POLICY_FILE") != "" || os.Getenv("NEVERLAUNCHER_GAME_TRUST_ROOT_PUBLIC_KEY") != ""
	production := strings.EqualFold(s.Config.Environment, "production") || strings.EqualFold(s.Config.Environment, "prod")
	if !configured && !production {
		return nil
	}
	p, e := currentGameTrust02312()
	if e != nil {
		return e
	}
	if manifest.TrustEpoch == 0 || manifest.TrustEpoch > p.Epoch {
		return errors.New("signed game manifest does not reference accepted trust epoch")
	}
	at, e := time.Parse(time.RFC3339Nano, manifest.Signature.SignedAt)
	if e != nil {
		return e
	}
	return authorizedGameSigningKey02312(p, manifest.Signature.PublicKey, at, false)
}
