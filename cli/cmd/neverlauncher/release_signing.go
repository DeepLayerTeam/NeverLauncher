package main

import (
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
		privateKeyPath = strings.TrimSpace(os.Getenv("NEVERLAUNCHER_RELEASE_SIGNING_PRIVATE_KEY_FILE"))
	}
	if privateKeyPath == "" {
		return errors.New("релиз подписание требует --закрытый-ключ или NEVERLAUNCHER_RELEASE_SIGNING_PRIVATE_KEY_FILE")
	}
	if err := ensureKeyOutsideReleaseBundle(dir, privateKeyPath); err != nil {
		return err
	}
	privateKey, err := loadEd25519PrivateKey(privateKeyPath)
	if err != nil {
		return fmt.Errorf("релиз ключ подписи: %w", err)
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
		return fmt.Errorf("PROVENANCE.JSON обязателен для подписанный аттестация: %w", err)
	}
	return signDetachedFileWithKey(provenance, filepath.Join(dir, "PROVENANCE.json.sig"), privateKey)
}

func verifyReleaseSignature(dir, publicKeyPath string) error {
	publicKeyPath = strings.TrimSpace(publicKeyPath)
	if publicKeyPath == "" {
		publicKeyPath = strings.TrimSpace(os.Getenv("NEVERLAUNCHER_RELEASE_SIGNING_PUBLIC_KEY_FILE"))
	}
	if publicKeyPath == "" {
		return errors.New("релиз проверка требует --публичный-ключ или NEVERLAUNCHER_RELEASE_SIGNING_PUBLIC_KEY_FILE; комплект ключ не считается якорь доверия")
	}
	if err := ensureKeyOutsideReleaseBundle(dir, publicKeyPath); err != nil {
		return err
	}
	publicKey, err := loadEd25519PublicKey(publicKeyPath)
	if err != nil {
		return fmt.Errorf("релиз проверка ключ: %w", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return err
	}
	sigRaw, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS.sig"))
	if err != nil {
		return errors.New("SHA256SUMS.sig отсутствует: комплект релиза должен быть подписан Ed25519")
	}
	var envelope releaseSignatureEnvelope
	if err := json.Unmarshal(sigRaw, &envelope); err != nil {
		return fmt.Errorf("SHA256SUMS.sig не является NeverLauncher Ed25519 подпись конверт: %w", err)
	}
	if envelope.Algorithm != "Ed25519" || envelope.SignedFile != "SHA256SUMS" {
		return fmt.Errorf("неподдерживаемая релиз подпись: algorithm=%q signedFile=%q", envelope.Algorithm, envelope.SignedFile)
	}
	digest := sha256.Sum256(data)
	if !strings.EqualFold(envelope.SHA256, hex.EncodeToString(digest[:])) {
		return errors.New("SHA256SUMS хеш не совпадает с SHA256SUMS.sig")
	}
	pubDigest := sha256.Sum256(publicKey)
	fingerprint := "sha256:" + hex.EncodeToString(pubDigest[:])
	if !strings.EqualFold(envelope.KeyFingerprint, fingerprint) {
		return fmt.Errorf("релиз подпись создана другим ключом: получил=%s доверенный=%s", envelope.KeyFingerprint, fingerprint)
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("некорректная Ed25519 подпись encoding")
	}
	if !ed25519.Verify(publicKey, data, signature) {
		return errors.New("Ed25519 проверка ошибка для SHA256SUMS")
	}
	if err := verifyDetachedFileWithKey(filepath.Join(dir, "PROVENANCE.json"), filepath.Join(dir, "PROVENANCE.json.sig"), publicKey); err != nil {
		return fmt.Errorf("SLSA происхождение аттестация: %w", err)
	}
	return nil
}

func ensureKeyOutsideReleaseBundle(dir, keyPath string) error {
	bundleAbs, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return err
	}
	keyAbs, err := filepath.Abs(filepath.Clean(keyPath))
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(bundleAbs, keyAbs)
	if err != nil {
		return err
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
		return errors.New("релиз signing/verification ключ должен находиться вне комплект релиза")
	}
	return nil
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
			return nil, errors.New("PEM закрытый ключ не Ed25519")
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
		return ed25519.PrivateKey(decoded), nil
	default:
		return nil, fmt.Errorf("Ed25519 закрытый ключ должен иметь 32-byte начальное значение или 64-byte закрытый ключ, получено %d байты", len(decoded))
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
			return nil, errors.New("PEM открытый ключ не Ed25519")
		}
		return ed, nil
	}
	decoded, err := decodeKeyMaterial(trimmed)
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("Ed25519 открытый ключ должен иметь 32 байты, получено %d", len(decoded))
	}
	return ed25519.PublicKey(decoded), nil
}

func decodeKeyMaterial(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("ключ файл пуст")
	}
	if decoded, err := hex.DecodeString(value); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return nil, errors.New("ключ должен быть PEM, hex или основа64")
}

func verifyDetachedEd25519(path, signaturePath, publicKeyPath string) (map[string]any, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("--путь обязателен")
	}
	if signaturePath == "" {
		signaturePath = path + ".sig"
	}
	publicKeyPath = strings.TrimSpace(publicKeyPath)
	if publicKeyPath == "" {
		publicKeyPath = strings.TrimSpace(os.Getenv("NEVERLAUNCHER_RELEASE_SIGNING_PUBLIC_KEY_FILE"))
	}
	if publicKeyPath == "" {
		return nil, errors.New("--публичный-ключ или NEVERLAUNCHER_RELEASE_SIGNING_PUBLIC_KEY_FILE обязателен")
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
		return nil, errors.New("отсоединённый подпись должна быть основа64 или hex")
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, data, sig) {
		return nil, errors.New("Ed25519 подпись проверка ошибка")
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
		return errors.New("Ed25519 отсоединённый подпись проверка ошибка")
	}
	return nil
}
