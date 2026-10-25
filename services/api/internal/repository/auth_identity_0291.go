package repository

import (
	"crypto/sha256"
	"encoding/hex"
)

func scopedAuthIdentityID0291(provider, issuer, userID string) string {
	digest := sha256.Sum256([]byte(provider + "\x00" + issuer + "\x00" + userID))
	return "identity-" + hex.EncodeToString(digest[:16])
}
