// Package prestarter implements the Java-free, signed first-run installer.
package prestarter

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const maxConfigBytes = 1024 * 1024

// Signature covers the *exact* payload bytes. Unknown fields are rejected;
// there is no JSON canonicalization ambiguity between signer and verifier.
type Envelope struct {
	KeyID         string `json:"keyId,omitempty"`
	TrustEpoch    uint64 `json:"trustEpoch,omitempty"`
	SignedAt      string `json:"signedAt,omitempty"`
	SchemaVersion string `json:"schemaVersion"`
	Payload       string `json:"payload"`
	Signature     string `json:"signature"`
}
type Artifact struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type Component struct {
	Name string `json:"name"`
	Artifact
}
type Target struct {
	OS         string      `json:"os"`
	Arch       string      `json:"arch"`
	Components []Component `json:"components"`
}

// Branding and InstallerTargets are part of the *signed* payload. Never use a
// mutable bundle header to choose display identity or installer executables.
type Branding struct {
	DisplayName     string          `json:"displayName"`
	Publisher       string          `json:"publisher"`
	WebsiteURL      string          `json:"websiteUrl,omitempty"`
	AccentColor     string          `json:"accentColor,omitempty"`
	BackgroundColor string          `json:"backgroundColor,omitempty"`
	TextColor       string          `json:"textColor,omitempty"`
	LogoPNG         string          `json:"logoPng,omitempty"`
	IconPNG         string          `json:"iconPng,omitempty"`
	SplashPNG       string          `json:"splashPng,omitempty"`
	Locale          string          `json:"locale,omitempty"`
	News            []BrandNews0355 `json:"news,omitempty"`
}
type InstallerTarget struct {
	OS         string   `json:"os"`
	Arch       string   `json:"arch"`
	Prestarter Artifact `json:"prestarter"`
}
type Config struct {
	SchemaVersion    string            `json:"schemaVersion"`
	ProjectID        string            `json:"projectId"`
	ProfileID        string            `json:"profileId"`
	Channel          string            `json:"channel"`
	BackendURL       string            `json:"backendUrl,omitempty"`
	ServerID         string            `json:"serverId,omitempty"`
	ServerHost       string            `json:"serverHost,omitempty"`
	ServerPort       uint16            `json:"serverPort,omitempty"`
	AutoEnter        bool              `json:"autoEnter,omitempty"`
	ProfilePublicKey string            `json:"profilePublicKey"`
	Manifest         Artifact          `json:"manifest"`
	JavaManifest     Artifact          `json:"javaManifest"`
	Targets          []Target          `json:"targets"`
	Branding         *Branding         `json:"branding,omitempty"`
	InstallerTargets []InstallerTarget `json:"installerTargets,omitempty"`
}

func decodeStrict(data []byte, dest any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return errors.New("trailing JSON value")
	} else if !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}
func SignedEnvelope(payload []byte, private ed25519.PrivateKey) ([]byte, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("Ed25519 signing key must be 64 bytes")
	}
	var cfg Config
	if err := decodeStrict(payload, &cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(Envelope{SchemaVersion: "1.0", Payload: base64.StdEncoding.EncodeToString(payload), Signature: hex.EncodeToString(ed25519.Sign(private, payload))}, "", "  ")
}
func VerifyEnvelope(data []byte, pinnedKeyHex string) (Config, string, error) {
	return VerifyEnvelopeWithPolicy(data, pinnedKeyHex, nil)
}

func VerifyEnvelopeWithPolicy(data []byte, pinnedKeyHex string, policy *TrustPolicy) (Config, string, error) {
	var cfg Config
	if len(data) > maxConfigBytes {
		return cfg, "", errors.New("signed config too large")
	}
	pinnedKeyHex = strings.TrimSpace(pinnedKeyHex)
	key, err := hex.DecodeString(pinnedKeyHex)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return cfg, "", errors.New("trusted key must be pre-provisioned 32-byte Ed25519 hex")
	}
	var envelope Envelope
	if err := decodeStrict(data, &envelope); err != nil {
		return cfg, "", err
	}
	if envelope.SchemaVersion != "1.0" && envelope.SchemaVersion != "2.0" {
		return cfg, "", errors.New("unsupported envelope schema")
	}
	if envelope.SchemaVersion == "2.0" {
		if policy == nil || envelope.TrustEpoch != policy.Epoch {
			return cfg, "", errors.New("root-signed delegated bootstrap policy/epoch required")
		}
		if envelope.KeyID == "" {
			return cfg, "", errors.New("bootstrap signer keyId missing")
		}
	}
	raw, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || len(raw) > maxConfigBytes {
		return cfg, "", errors.New("invalid signed payload")
	}
	sig, err := hex.DecodeString(envelope.Signature)
	if envelope.SchemaVersion == "2.0" {
		delegated := false
		for _, k := range policy.Keys {
			if k.ID != envelope.KeyID || k.Role != "bootstrap" {
				continue
			}
			t, e := strictTime02312(envelope.SignedAt)
			if e != nil {
				return cfg, "", e
			}
			if e = policy.Authorize("bootstrap", k.ID, k.PublicKey, t, time.Now().UTC(), true); e != nil {
				return cfg, "", e
			}
			key, _ = hex.DecodeString(k.PublicKey)
			delegated = true
			break
		}
		if !delegated {
			return cfg, "", errors.New("bootstrap signer not delegated by signed policy")
		}
	}
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(key), bootstrapSignaturePayload02312(raw, envelope), sig) {
		return cfg, "", errors.New("signed bootstrap config failed Ed25519 verification")
	}
	if err := decodeStrict(raw, &cfg); err != nil {
		return cfg, "", err
	}
	if err := cfg.Validate(); err != nil {
		return cfg, "", err
	}
	digest := sha256.Sum256(raw)
	return cfg, hex.EncodeToString(digest[:]), nil
}
func validID(s string) bool {
	if len(s) == 0 || len(s) > 96 || s == "." || s == ".." || strings.HasSuffix(s, ".") || strings.HasSuffix(s, " ") {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}
func validDigest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == sha256.Size && s == strings.ToLower(s)
}
func validateArtifact(a Artifact) error {
	if !validDigest(a.SHA256) || a.Size < 1 || a.Size > int64(3<<30) {
		return errors.New("invalid artifact digest/size")
	}
	u, e := url.Parse(a.URL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return fmt.Errorf("artifact URL must be fixed HTTPS without credentials/fragment/query: %q", a.URL)
	}
	return nil
}
func (c Config) Validate() error {
	if c.SchemaVersion != "1.0" || !validID(c.ProjectID) || !validID(c.ProfileID) || !validID(c.Channel) {
		return errors.New("invalid bootstrap identity")
	}
	if c.BackendURL != "" {
		u, e := url.Parse(c.BackendURL)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return errors.New("backendUrl must be HTTPS without credentials or fragment")
		}
	}
	if c.ServerID != "" && !validID(c.ServerID) {
		return errors.New("invalid serverId")
	}
	if c.AutoEnter && (c.ServerID == "" || c.ServerHost == "" || c.ServerPort == 0) {
		return errors.New("autoEnter needs a signed serverId, public serverHost and serverPort")
	}
	if c.ServerHost != "" {
		if len(c.ServerHost) > 253 || strings.Contains(c.ServerHost, "..") || strings.HasPrefix(c.ServerHost, ".") || strings.HasSuffix(c.ServerHost, ".") {
			return errors.New("invalid signed serverHost")
		}
		for _, part := range strings.Split(c.ServerHost, ".") {
			if part == "" || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
				return errors.New("invalid signed serverHost label")
			}
			for _, c := range part {
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
					return errors.New("invalid signed serverHost character")
				}
			}
		}
	}
	if c.Manifest.Size > 16*1024*1024 || c.JavaManifest.Size > 8*1024*1024 {
		return errors.New("bootstrap manifest size limit exceeded")
	}
	if !validDigest(c.Manifest.SHA256) || !validDigest(c.JavaManifest.SHA256) {
		return errors.New("manifest digest must be pinned")
	}
	if b, e := hex.DecodeString(c.ProfilePublicKey); e != nil || len(b) != 32 {
		return errors.New("invalid signed profile public key")
	}
	if e := validateArtifact(c.Manifest); e != nil {
		return fmt.Errorf("game manifest: %w", e)
	}
	if e := validateArtifact(c.JavaManifest); e != nil {
		return fmt.Errorf("Java distribution manifest: %w", e)
	}
	if len(c.Targets) == 0 || len(c.Targets) > 24 {
		return errors.New("no supported target")
	}
	seen := map[string]bool{}
	for _, t := range c.Targets {
		if (t.OS != "linux" && t.OS != "windows" && t.OS != "darwin") || (t.Arch != "amd64" && t.Arch != "arm64") {
			return errors.New("unsupported OS/arch in bootstrap config")
		}
		id := t.OS + "/" + t.Arch
		if seen[id] {
			return errors.New("duplicate platform target")
		}
		seen[id] = true
		found := map[string]bool{}
		if len(t.Components) != 3 {
			return fmt.Errorf("%s: require exactly neverruntime, desktop, guard components", id)
		}
		for _, a := range t.Components {
			if a.Name != "neverruntime" && a.Name != "desktop" && a.Name != "guard" {
				return fmt.Errorf("invalid component role: %s", a.Name)
			}
			if found[a.Name] {
				return errors.New("duplicate component")
			}
			found[a.Name] = true
			if e := validateArtifact(a.Artifact); e != nil {
				return fmt.Errorf("%s: %w", a.Name, e)
			}
		}
		for _, role := range []string{"neverruntime", "desktop", "guard"} {
			if !found[role] {
				return fmt.Errorf("missing component %s", role)
			}
		}
	}
	if c.Branding != nil {
		if err := c.Branding.Validate0355(); err != nil {
			return err
		}
	}
	installerTargets := make(map[string]bool)
	for _, target := range c.InstallerTargets {
		id := target.OS + "/" + target.Arch
		if installerTargets[id] || !seen[id] {
			return fmt.Errorf("duplicate/unknown installer target %s", id)
		}
		installerTargets[id] = true
		if err := validateArtifact(target.Prestarter); err != nil {
			return fmt.Errorf("invalid prestarter for %s: %w", id, err)
		}
	}
	return nil
}
func (c Config) InstallerFor(osName, arch string) (Artifact, error) {
	for _, target := range c.InstallerTargets {
		if target.OS == osName && target.Arch == arch {
			return target.Prestarter, nil
		}
	}
	return Artifact{}, fmt.Errorf("no signed prestarter for %s/%s", osName, arch)
}
func (c Config) SelectTarget() (Target, error) {
	for _, t := range c.Targets {
		if t.OS == runtime.GOOS && t.Arch == runtime.GOARCH {
			return t, nil
		}
	}
	return Target{}, fmt.Errorf("unsupported platform %s/%s", runtime.GOOS, runtime.GOARCH)
}
func ComponentName(role string) string {
	switch role {
	case "neverruntime":
		return "neverruntime" + exeSuffix()
	case "desktop":
		return "neverlauncher-desktop" + exeSuffix()
	case "guard":
		return "guard" + exeSuffix()
	}
	panic("unvalidated component role")
}
func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}
func safeRoot(root string) (string, error) {
	if !filepath.IsAbs(root) {
		return "", errors.New("installation root must be absolute")
	}
	cleaned := filepath.Clean(root)
	if e := os.MkdirAll(cleaned, 0700); e != nil {
		return "", e
	}
	resolved, e := filepath.EvalSymlinks(cleaned)
	if e != nil {
		return "", e
	}
	if resolved != cleaned {
		return "", errors.New("installation root must not include symlinks/junctions")
	}
	return cleaned, nil
}
