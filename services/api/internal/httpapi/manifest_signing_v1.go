package httpapi

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func (s Server) manifestSigningPrivateKey() (ed25519.PrivateKey, error) {
	seedHex := strings.TrimSpace(s.Config.ManifestSigningPrivateKey)
	if seedHex == "" {
		if strings.EqualFold(s.Config.Environment, "production") || strings.EqualFold(s.Config.Environment, "prod") {
			return nil, errors.New("NEVERLAUNCHER_MANIFEST_SIGNING_PRIVATE_KEY обязателен для production publish")
		}
		dev := sha256.Sum256([]byte("NeverLauncher development signing key - never use in production"))
		seedHex = hex.EncodeToString(dev[:])
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("manifest signing key должен быть 32-byte Ed25519 seed в hex")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func (s Server) signManifest(manifest model.Manifest) (model.Manifest, error) {
	privateKey, err := s.manifestSigningPrivateKey()
	if err != nil {
		return model.Manifest{}, err
	}
	manifest.Signature = nil
	payload, err := json.Marshal(manifest)
	if err != nil {
		return model.Manifest{}, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	manifest.Signature = &model.SignatureInfo{Algorithm: "Ed25519", PublicKey: hex.EncodeToString(publicKey), Signature: hex.EncodeToString(ed25519.Sign(privateKey, payload)), SignedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	return manifest, nil
}

func (s Server) verifyManifestSignature(manifest model.Manifest) error {
	if manifest.Signature == nil || !strings.EqualFold(manifest.Signature.Algorithm, "Ed25519") {
		return errors.New("manifest не имеет Ed25519-подписи")
	}
	privateKey, err := s.manifestSigningPrivateKey()
	if err != nil {
		return err
	}
	trustedPublicKey := privateKey.Public().(ed25519.PublicKey)
	declaredPublicKey, err := hex.DecodeString(strings.TrimSpace(manifest.Signature.PublicKey))
	if err != nil || len(declaredPublicKey) != ed25519.PublicKeySize {
		return errors.New("manifest содержит некорректный Ed25519 public key")
	}
	if !ed25519.PublicKey(declaredPublicKey).Equal(trustedPublicKey) {
		return errors.New("manifest подписан недоверенным Ed25519 key")
	}
	signature, err := hex.DecodeString(strings.TrimSpace(manifest.Signature.Signature))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("manifest содержит некорректную Ed25519 signature")
	}
	unsigned := manifest
	unsigned.Signature = nil
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return err
	}
	if !ed25519.Verify(trustedPublicKey, payload, signature) {
		return errors.New("Ed25519 signature manifest не прошла криптографическую проверку")
	}
	return nil
}

func ValidateManifestSigningConfig(seedHex string) error {
	seed, err := hex.DecodeString(strings.TrimSpace(seedHex))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("NEVERLAUNCHER_MANIFEST_SIGNING_PRIVATE_KEY должен содержать 64 hex-символа (32-byte Ed25519 seed)")
	}
	return nil
}
