package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func componentTrustRequired02312(v string) bool {
	a, b, c, ok := parseCoreVersion(v)
	return ok && (a > 0 || b > 23 || (b == 23 && c >= 12))
}
func loadComponentPolicy02312(manifestPath string) (TrustPolicy, string, componentSignature02312, error) {
	var env componentSignature02312
	path := filepath.Join(filepath.Dir(manifestPath), componentPolicyFile02312)
	raw, e := os.ReadFile(path)
	if e != nil {
		return TrustPolicy{}, "", env, e
	}
	// Unlike the v1 signer, the v2 delegation root MUST be independently provisioned.
	p, digest, e := VerifyTrustPolicy(raw, componentSetRootKey02312, time.Now().UTC())
	if e != nil {
		return p, "", env, e
	}
	sigRaw, e := os.ReadFile(filepath.Join(filepath.Dir(manifestPath), componentSignatureFile02312))
	if e != nil {
		return p, "", env, e
	}
	if len(sigRaw) > 4096 || decodeStrict(sigRaw, &env) != nil {
		return p, "", env, errors.New("invalid component signature v2")
	}
	if env.SchemaVersion != "2.0" || env.Algorithm != "ed25519" || env.TrustEpoch != p.Epoch || env.PolicySHA256 != digest {
		return p, "", env, errors.New("component trust epoch/policy mismatch")
	}
	return p, digest, env, nil
}
func verifyComponentTrust02312(manifestPath string) error {
	policy, _, env, e := loadComponentPolicy02312(manifestPath)
	if e != nil {
		return e
	}
	raw, e := os.ReadFile(manifestPath)
	if e != nil {
		return e
	}
	h := sha256.Sum256(raw)
	if !strings.EqualFold(env.ManifestSHA256, hex.EncodeToString(h[:])) {
		return errors.New("component v2 digest mismatch")
	}
	signedAt, e := strictTime02312(env.SignedAt)
	if e != nil {
		return e
	}
	// Enforce active issuance, not merely validity at a historical date: a
	// revoked or retired signer may not authorize a NEW update.
	var pub []byte
	for _, k := range policy.Keys {
		if k.ID == env.KeyID && k.Role == "component" {
			if e = policy.Authorize("component", env.KeyID, k.PublicKey, signedAt, time.Now().UTC(), true); e != nil {
				return e
			}
			pub, _ = hex.DecodeString(k.PublicKey)
			break
		}
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("component signer %s not delegated", env.KeyID)
	}
	sig, e := hex.DecodeString(env.Signature)
	if e != nil || len(sig) != 64 || !ed25519.Verify(ed25519.PublicKey(pub), componentTrustSignaturePayload02312(raw, env), sig) {
		return errors.New("delegated component Ed25519 signature invalid")
	}
	return nil
}
func acceptComponentTrust02312(root, manifestPath string) error {
	if e := verifyComponentTrust02312(manifestPath); e != nil {
		return e
	}
	raw, e := os.ReadFile(filepath.Join(filepath.Dir(manifestPath), componentPolicyFile02312))
	if e != nil {
		return e
	}
	_, e = AcceptTrustPolicy(filepath.Join(root, ".launcher", "component-trust"), componentSetRootKey02312, raw, time.Now().UTC())
	return e
}

// Support explicitly separately signed v2 metadata while retaining v1 sidecar
// for upgrading a 0.23.11 installation through its existing external updater.
func checkComponentTrustSet02312(root, manifestPath string, m componentUpdateManifest0157) error {
	if !componentTrustRequired02312(m.ProductVersion) {
		return nil
	}
	return acceptComponentTrust02312(root, manifestPath)
}

func componentTrustSignaturePayload02312(raw []byte, env componentSignature02312) []byte {
	prefix := "Launcher-Component-v2\n" + env.KeyID + "\n" + strconv.FormatUint(env.TrustEpoch, 10) + "\n" + env.PolicySHA256 + "\n" + env.ManifestSHA256 + "\n" + env.SignedAt + "\n"
	return append([]byte(prefix), raw...)
}
