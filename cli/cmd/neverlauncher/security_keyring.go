package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type securityKeyRecord struct {
	ID            string `json:"id"`
	Purpose       string `json:"purpose"`
	Algorithm     string `json:"algorithm"`
	Fingerprint   string `json:"fingerprint"`
	PublicKeyFile string `json:"publicKeyFile"`
	Status        string `json:"status"`
	CreatedAt     string `json:"createdAt"`
	RetiredAt     string `json:"retiredAt,omitempty"`
	RevokedAt     string `json:"revokedAt,omitempty"`
	ReplacedBy    string `json:"replacedBy,omitempty"`
}
type securityKeyRegistry struct {
	SchemaVersion string              `json:"schemaVersion"`
	ToolVersion   string              `json:"toolVersion"`
	UpdatedAt     string              `json:"updatedAt"`
	TrustEpoch    uint64              `json:"trustEpoch,omitempty"`
	Keys          []securityKeyRecord `json:"keys"`
}

func securityRegistryDir(args []string) string {
	if v := flagValue(args, "--registry-dir", ""); v != "" {
		return filepath.Clean(v)
	}
	if v := os.Getenv("NEVERLAUNCHER_SECURITY_REGISTRY_DIR"); v != "" {
		return filepath.Clean(v)
	}
	return filepath.Clean(".neverlauncher/security")
}
func registryPath(dir string) string { return filepath.Join(dir, "trusted-keys.json") }
func loadKeyRegistry(dir string) (securityKeyRegistry, error) {
	raw, err := os.ReadFile(registryPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return securityKeyRegistry{SchemaVersion: cliSchemaVersion, ToolVersion: version, Keys: []securityKeyRecord{}}, nil
	}
	if err != nil {
		return securityKeyRegistry{}, err
	}
	var r securityKeyRegistry
	if err := json.Unmarshal(raw, &r); err != nil {
		return r, err
	}
	if r.Keys == nil {
		r.Keys = []securityKeyRecord{}
	}
	return r, nil
}
func saveKeyRegistry(dir string, r securityKeyRegistry) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	r.SchemaVersion = cliSchemaVersion
	r.ToolVersion = version
	r.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return writeJSONFileAtomicMode(registryPath(dir), r, 0o600)
}

func rotateSecurityKey(args []string) (map[string]any, error) {
	dir := securityRegistryDir(args)
	purpose := flagValue(args, "--key", "release-signing")
	revokePrevious := flagValue(args, "--revoke-previous", "false") == "true"
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	fpRaw := sha256.Sum256(pub)
	fp := "sha256:" + hex.EncodeToString(fpRaw[:])
	id := fmt.Sprintf("%s-%s-%s", safeArtifactName(purpose), time.Now().UTC().Format("20060102T150405Z"), hex.EncodeToString(fpRaw[:4]))
	privatePath := flagValue(args, "--private-key-out", filepath.Join(dir, "private", id+".pem"))
	publicPath := flagValue(args, "--public-key-out", filepath.Join(dir, "public", id+".pem"))
	if err := os.MkdirAll(filepath.Dir(privatePath), 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(publicPath), 0o755); err != nil {
		return nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pubder, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubder}), 0o644); err != nil {
		return nil, err
	}
	reg, err := loadKeyRegistry(dir)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for i := range reg.Keys {
		if reg.Keys[i].Purpose == purpose && reg.Keys[i].Status == "active" {
			reg.Keys[i].ReplacedBy = id
			reg.Keys[i].RetiredAt = now
			if revokePrevious {
				reg.Keys[i].Status = "revoked"
				reg.Keys[i].RevokedAt = now
			} else {
				reg.Keys[i].Status = "verify-only"
			}
		}
	}
	rec := securityKeyRecord{ID: id, Purpose: purpose, Algorithm: "Ed25519", Fingerprint: fp, PublicKeyFile: publicPath, Status: "active", CreatedAt: now}
	reg.Keys = append(reg.Keys, rec)
	if purpose == "release-signing" {
		reg.TrustEpoch++
	}
	if err := saveKeyRegistry(dir, reg); err != nil {
		return nil, err
	}
	return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "status": "rotated", "trustEpoch": reg.TrustEpoch, "key": rec, "privateKeyFile": privatePath, "registry": registryPath(dir)}, nil
}

func securityRevocations(args []string) (map[string]any, error) {
	dir := securityRegistryDir(args)
	reg, err := loadKeyRegistry(dir)
	if err != nil {
		return nil, err
	}
	revokeID := flagValue(args, "--revoke", "")
	if revokeID != "" {
		found := false
		now := time.Now().UTC().Format(time.RFC3339Nano)
		for i := range reg.Keys {
			if reg.Keys[i].ID == revokeID {
				found = true
				reg.Keys[i].Status = "revoked"
				reg.Keys[i].RevokedAt = now
			}
		}
		if !found {
			return nil, fmt.Errorf("key %s не найден", revokeID)
		}
		reg.TrustEpoch++
		if err := saveKeyRegistry(dir, reg); err != nil {
			return nil, err
		}
	}
	revoked := []securityKeyRecord{}
	for _, k := range reg.Keys {
		if k.Status == "revoked" {
			revoked = append(revoked, k)
		}
	}
	sort.Slice(revoked, func(i, j int) bool { return revoked[i].ID < revoked[j].ID })
	return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "registry": registryPath(dir), "trustEpoch": reg.TrustEpoch, "status": "loaded", "revoked": revoked, "count": len(revoked)}, nil
}

func securityKeys(args []string) (map[string]any, error) {
	dir := securityRegistryDir(args)
	reg, err := loadKeyRegistry(dir)
	if err != nil {
		return nil, err
	}
	return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "registry": registryPath(dir), "trustEpoch": reg.TrustEpoch, "keys": reg.Keys, "count": len(reg.Keys)}, nil
}

func ensurePublicKeyNotRevoked(registryDir, publicKeyPath string) error {
	if strings.TrimSpace(registryDir) == "" {
		return nil
	}
	if strings.TrimSpace(publicKeyPath) == "" {
		publicKeyPath = strings.TrimSpace(os.Getenv("NEVERLAUNCHER_RELEASE_SIGNING_PUBLIC_KEY_FILE"))
	}
	if publicKeyPath == "" {
		return errors.New("revocation check требует trusted public key")
	}
	pub, err := loadEd25519PublicKey(publicKeyPath)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(pub)
	fp := "sha256:" + hex.EncodeToString(sum[:])
	reg, err := loadKeyRegistry(registryDir)
	if err != nil {
		return err
	}
	for _, k := range reg.Keys {
		if strings.EqualFold(k.Fingerprint, fp) && k.Status == "revoked" {
			return fmt.Errorf("trusted key revoked: %s", k.ID)
		}
	}
	return nil
}

func securityAttest(args []string) (map[string]any, error) {
	path := flagValue(args, "--path", "")
	if path == "" {
		return nil, errors.New("security attest требует --path <PROVENANCE.json или artifact>")
	}
	privateKeyPath := flagValue(args, "--private-key", os.Getenv("NEVERLAUNCHER_RELEASE_SIGNING_PRIVATE_KEY_FILE"))
	if privateKeyPath == "" {
		return nil, errors.New("security attest требует --private-key")
	}
	priv, err := loadEd25519PrivateKey(privateKeyPath)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, data)
	pub := priv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	sigPath := flagValue(args, "--signature", path+".sig")
	if err := os.WriteFile(sigPath, []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644); err != nil {
		return nil, err
	}
	return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "status": "attested", "predicate": path, "signature": sigPath, "algorithm": "Ed25519", "keyFingerprint": "sha256:" + hex.EncodeToString(sum[:])}, nil
}

func writeJSONFileAtomicMode(path string, payload any, mode os.FileMode) error {
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
