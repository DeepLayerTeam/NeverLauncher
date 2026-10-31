package httpapi

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func (s Server) manifestSigningPrivateKey() (ed25519.PrivateKey, error) {
	seedHex := strings.TrimSpace(s.Config.ManifestSigningPrivateKey)
	if seedHex == "" {
		if strings.EqualFold(s.Config.Environment, "production") || strings.EqualFold(s.Config.Environment, "prod") {
			return nil, errors.New("LAUNCHER_MANIFEST_SIGNING_PRIVATE_KEY обязателен для production publish")
		}
		dev := sha256.Sum256([]byte("Launcher development signing key - never use in production"))
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
	if err := s.enforceGameTrustSigning02312(&manifest, privateKey); err != nil {
		return model.Manifest{}, err
	}
	if err := model.ValidateManifestSchema(manifest); err != nil {
		return model.Manifest{}, err
	}
	// Publication must not bypass the Admin graph preflight through the legacy
	// manifest update route. Reject statically impossible signed v5 presets.
	if cat := manifest.ComponentCatalog; cat != nil && cat.SchemaVersion == model.ComponentCatalogSchema0245 {
		names := append([]string{""}, presetIDs0248(*cat)...)
		for _, name := range names {
			if _, err := model.PreviewCatalogGraph0248(*cat, name); err != nil {
				return model.Manifest{}, fmt.Errorf("component preset %q: %w", name, err)
			}
		}
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
	declaredPublicKey, err := hex.DecodeString(strings.TrimSpace(manifest.Signature.PublicKey))
	if err != nil || len(declaredPublicKey) != ed25519.PublicKeySize {
		return errors.New("invalid manifest public key")
	}
	configured := strings.TrimSpace(os.Getenv("LAUNCHER_GAME_TRUST_POLICY_FILE")) != "" || strings.TrimSpace(os.Getenv("LAUNCHER_GAME_TRUST_ROOT_PUBLIC_KEY")) != ""
	production := strings.EqualFold(s.Config.Environment, "production") || strings.EqualFold(s.Config.Environment, "prod")
	if !configured && !production {
		privateKey, e := s.manifestSigningPrivateKey()
		if e != nil {
			return e
		}
		if !ed25519.PublicKey(declaredPublicKey).Equal(privateKey.Public().(ed25519.PublicKey)) {
			return errors.New("manifest signer is not the configured key")
		}
	}
	signature, err := hex.DecodeString(strings.TrimSpace(manifest.Signature.Signature))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("manifest содержит некорректную Ed25519 signature")
	}
	if err := model.ValidateManifestSchema(manifest); err != nil {
		return err
	}
	unsigned := manifest
	unsigned.Signature = nil
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(declaredPublicKey), payload, signature) {
		return errors.New("Ed25519 signature manifest не прошла криптографическую проверку")
	}
	return s.enforceGameTrustVerify02312(manifest)
}

func ValidateManifestSigningConfig(seedHex string) error {
	seed, err := hex.DecodeString(strings.TrimSpace(seedHex))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("LAUNCHER_MANIFEST_SIGNING_PRIVATE_KEY должен содержать 64 hex-символа (32-byte Ed25519 seed)")
	}
	return nil
}
