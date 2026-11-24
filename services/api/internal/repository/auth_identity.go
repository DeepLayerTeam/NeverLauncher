package repository

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

func scopedAuthIdentityID0291(provider, issuer, userID string) string {
	digest := sha256.Sum256([]byte(provider + "\x00" + issuer + "\x00" + userID))
	return "identity-" + hex.EncodeToString(digest[:16])
}

// A new SkiF4er binding must not resurrect sessions from an earlier binding.
func newSkif4erIdentityID102() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "identity-" + hex.EncodeToString(raw[:]), nil
}
