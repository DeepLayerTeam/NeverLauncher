package main

import (
	"bytes"
	"crypto/ed25519"
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
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/cli/internal/releasekeypaths"
)

type releaseSignatureEnvelope struct {
	SchemaVersion  string `json:"schemaVersion"`
	Algorithm      string `json:"algorithm"`
	SignedFile     string `json:"signedFile"`
	SHA256         string `json:"sha256"`
	Signature      string `json:"signature"`
	KeyFingerprint string `json:"keyFingerprint"`
	SignedAt       string `json:"signedAt"`
}

func signReleaseBundle(dir, privateKeyPath string) error {
	privateKeyPath = strings.TrimSpace(privateKeyPath)
	if privateKeyPath == "" {
		privateKeyPath = strings.TrimSpace(os.Getenv("LAUNCHER_RELEASE_SIGNING_PRIVATE_KEY_FILE"))
	}
	if privateKeyPath == "" {
		return errors.New("release signing требует --private-key или LAUNCHER_RELEASE_SIGNING_PRIVATE_KEY_FILE")
	}
	if err := ensureKeyOutsideReleaseBundle(dir, privateKeyPath); err != nil {
		return err
	}
	privateKey, err := loadEd25519PrivateKey(privateKeyPath)
	if err != nil {
		return fmt.Errorf("release signing key: %w", err)
	}
	bundleVersion, versionErr := releaseBundleVersion(dir)
	if versionErr != nil {
		return fmt.Errorf("release BOM gate: %w", versionErr)
	}
	if err := verifyReleaseBOM03214(dir, bundleVersion); err != nil {
		return fmt.Errorf("refusing to sign inconsistent release BOM: %w", err)
	}
	if err := verifyReleaseBOMBinding03214(dir, bundleVersion); err != nil {
		return fmt.Errorf("refusing to sign unbound release BOM: %w", err)
	}
	if singleNodeGARequired0330(bundleVersion) {
		raw, err := os.ReadFile(filepath.Join(dir, "RELEASE_MANIFEST.json"))
		if err != nil {
			return err
		}
		var m struct {
			SourceCommit string `json:"sourceCommit"`
		}
		if err := json.Unmarshal(raw, &m); err != nil {
			return err
		}
		if err := verifySingleNodeGABundle0330(dir, bundleVersion, m.SourceCommit, ""); err != nil {
			return fmt.Errorf("refusing GA signature without independent certification: %w", err)
		}
		pubPath := os.Getenv("LAUNCHER_SINGLE_NODE_GA_PUBLIC_KEY_FILE")
		gaKey, err := loadEd25519PublicKey(pubPath)
		if err != nil {
			return err
		}
		if string(gaKey) == string(privateKey.Public().(ed25519.PublicKey)) {
			return errors.New("release and independent GA keys must be different")
		}
	}
	// Enforce independent exact-byte GA inside `launcher release sign` as
	// well as the production workflow: direct CLI calls cannot skip this gate.
	if gaTargetsRequired0361(bundleVersion) {
		manifestRaw, err := os.ReadFile(filepath.Join(dir, "RELEASE_MANIFEST.json"))
		if err != nil {
			return err
		}
		var m struct {
			SourceCommit string `json:"sourceCommit"`
		}
		if err := json.Unmarshal(manifestRaw, &m); err != nil {
			return err
		}
		if err := verifyGATargets0361(dir, bundleVersion, m.SourceCommit, privateKey.Public().(ed25519.PublicKey)); err != nil {
			return fmt.Errorf("refusing GA release signature: %w", err)
		}
	}
	if rehearsalRequired0365(bundleVersion) {
		manifestRaw, err := os.ReadFile(filepath.Join(dir, "RELEASE_MANIFEST.json"))
		if err != nil {
			return err
		}
		var manifest struct {
			SourceCommit string `json:"sourceCommit"`
		}
		if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
			return err
		}
		if err := verifyRehearsal0365(dir, bundleVersion, manifest.SourceCommit); err != nil {
			return fmt.Errorf("refusing GA release signature without valid production rehearsal: %w", err)
		}
	}
	if bundleVersion, err := releaseBundleVersion(dir); err == nil && releaseVerificationV2Required0158(bundleVersion) {
		return signReleaseBundleV20158(dir, privateKey)
	}
	data, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	pub := privateKey.Public().(ed25519.PublicKey)
	pubDigest := sha256.Sum256(pub)
	envelope := releaseSignatureEnvelope{
		SchemaVersion:  "1.0",
		Algorithm:      "Ed25519",
		SignedFile:     "SHA256SUMS",
		SHA256:         hex.EncodeToString(digest[:]),
		Signature:      base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, data)),
		KeyFingerprint: "sha256:" + hex.EncodeToString(pubDigest[:]),
		SignedAt:       time.Now().UTC().Format(time.RFC3339Nano),
	}
	payload, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS.sig"), append(payload, '\n'), 0o644); err != nil {
		return err
	}
	provenance := filepath.Join(dir, "PROVENANCE.json")
	if _, err := os.Stat(provenance); err != nil {
		return fmt.Errorf("PROVENANCE.json обязателен для signed attestation: %w", err)
	}
	return signDetachedFileWithKey(provenance, filepath.Join(dir, "PROVENANCE.json.sig"), privateKey)
}

func verifyReleaseSignature(dir, publicKeyPath string) error {
	publicKeyPath = strings.TrimSpace(publicKeyPath)
	if publicKeyPath == "" {
		publicKeyPath = strings.TrimSpace(os.Getenv("LAUNCHER_RELEASE_SIGNING_PUBLIC_KEY_FILE"))
	}
	if publicKeyPath == "" {
		return errors.New("release verification требует --public-key или LAUNCHER_RELEASE_SIGNING_PUBLIC_KEY_FILE; bundled key не считается trust anchor")
	}
	if err := ensureKeyOutsideReleaseBundle(dir, publicKeyPath); err != nil {
		return err
	}
	publicKey, err := loadEd25519PublicKey(publicKeyPath)
	if err != nil {
		return fmt.Errorf("release verification key: %w", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return err
	}
	sigRaw, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS.sig"))
	if err != nil {
		return errors.New("SHA256SUMS.sig отсутствует: release bundle должен быть подписан Ed25519")
	}
	var envelope releaseSignatureEnvelope
	if err := json.Unmarshal(sigRaw, &envelope); err != nil {
		return fmt.Errorf("SHA256SUMS.sig не является Launcher Ed25519 signature envelope: %w", err)
	}
	if envelope.Algorithm != "Ed25519" || envelope.SignedFile != "SHA256SUMS" {
		return fmt.Errorf("неподдерживаемая release signature: algorithm=%q signedFile=%q", envelope.Algorithm, envelope.SignedFile)
	}
	digest := sha256.Sum256(data)
	if !strings.EqualFold(envelope.SHA256, hex.EncodeToString(digest[:])) {
		return errors.New("SHA256SUMS digest не совпадает с SHA256SUMS.sig")
	}
	pubDigest := sha256.Sum256(publicKey)
	fingerprint := "sha256:" + hex.EncodeToString(pubDigest[:])
	if !strings.EqualFold(envelope.KeyFingerprint, fingerprint) {
		return fmt.Errorf("release signature создана другим ключом: got=%s trusted=%s", envelope.KeyFingerprint, fingerprint)
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("некорректная Ed25519 signature encoding")
	}
	if !ed25519.Verify(publicKey, data, signature) {
		return errors.New("Ed25519 verification failed для SHA256SUMS")
	}
	if err := verifyDetachedFileWithKey(filepath.Join(dir, "PROVENANCE.json"), filepath.Join(dir, "PROVENANCE.json.sig"), publicKey); err != nil {
		return fmt.Errorf("SLSA provenance attestation: %w", err)
	}
	return nil
}

func ensureKeyOutsideReleaseBundle(dir, keyPath string) error {
	return releasekeypaths.OutsideBundle(dir, keyPath)
}

func loadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(data))
	if block, _ := pem.Decode(data); block != nil {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ed, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("PEM private key не Ed25519")
		}
		return ed, nil
	}
	decoded, err := decodeKeyMaterial(trimmed)
	if err != nil {
		return nil, err
	}
	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	case ed25519.PrivateKeySize:
		canonical := ed25519.NewKeyFromSeed(decoded[:ed25519.SeedSize])
		if !bytes.Equal(decoded, canonical) {
			return nil, errors.New("Ed25519 private key has inconsistent public component")
		}
		return canonical, nil
	default:
		return nil, fmt.Errorf("Ed25519 private key должен иметь 32-byte seed или 64-byte private key, получено %d bytes", len(decoded))
	}
}

func loadEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(data))
	if block, _ := pem.Decode(data); block != nil {
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ed, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("PEM public key не Ed25519")
		}
		return ed, nil
	}
	decoded, err := decodeKeyMaterial(trimmed)
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("Ed25519 public key должен иметь 32 bytes, получено %d", len(decoded))
	}
	return ed25519.PublicKey(decoded), nil
}

func decodeKeyMaterial(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("key file пуст")
	}
	if decoded, err := hex.DecodeString(value); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return nil, errors.New("key должен быть PEM, hex или base64")
}

func verifyDetachedEd25519(path, signaturePath, publicKeyPath string) (map[string]any, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("--path обязателен")
	}
	if signaturePath == "" {
		signaturePath = path + ".sig"
	}
	publicKeyPath = strings.TrimSpace(publicKeyPath)
	if publicKeyPath == "" {
		publicKeyPath = strings.TrimSpace(os.Getenv("LAUNCHER_RELEASE_SIGNING_PUBLIC_KEY_FILE"))
	}
	if publicKeyPath == "" {
		return nil, errors.New("--public-key или LAUNCHER_RELEASE_SIGNING_PUBLIC_KEY_FILE обязателен")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sigData, err := os.ReadFile(signaturePath)
	if err != nil {
		return nil, err
	}
	pub, err := loadEd25519PublicKey(publicKeyPath)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(sigData))
	var sig []byte
	if decoded, err := base64.StdEncoding.DecodeString(text); err == nil {
		sig = decoded
	} else if decoded, err := hex.DecodeString(text); err == nil {
		sig = decoded
	} else {
		return nil, errors.New("detached signature должна быть base64 или hex")
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, data, sig) {
		return nil, errors.New("Ed25519 signature verification failed")
	}
	digest := sha256.Sum256(data)
	pubDigest := sha256.Sum256(pub)
	return map[string]any{
		"schemaVersion":  cliSchemaVersion,
		"toolVersion":    version,
		"status":         "verified",
		"algorithm":      "Ed25519",
		"path":           path,
		"signature":      signaturePath,
		"sha256":         hex.EncodeToString(digest[:]),
		"keyFingerprint": "sha256:" + hex.EncodeToString(pubDigest[:]),
	}, nil
}

func signDetachedFileWithKey(path, signaturePath string, privateKey ed25519.PrivateKey) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(privateKey, data)
	return os.WriteFile(signaturePath, []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644)
}

func verifyDetachedFileWithKey(path, signaturePath string, publicKey ed25519.PublicKey) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(signaturePath)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(publicKey, data, sig) {
		return errors.New("Ed25519 detached signature verification failed")
	}
	return nil
}
