// Package bridgeidentity checks that a Minecraft runtime's observed UUID is
// consistent with the identity authorised by the one-time ServerBridge ticket.
// Empty observed UUIDs are permitted for pre-login proxy gates, which have not
// yet completed Mojang/authlib authentication and cannot assert a UUID.
package bridgeidentity

import (
	"errors"
	"strings"
)

var (
	ErrInvalidAuthorizedUUID = errors.New("serverbridge_authorized_uuid_invalid")
	ErrInvalidObservedUUID   = errors.New("serverbridge_player_uuid_invalid")
	ErrIdentityMismatch      = errors.New("serverbridge_player_uuid_mismatch")
)

// CanonicalUUID accepts only the wire UUID formats supported by Minecraft:
// 32 hex digits or the canonical 8-4-4-4-12 form. Do not accept arbitrary
// punctuation-stripped strings or UUID prefixes.
func CanonicalUUID(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if len(raw) == 36 {
		for _, i := range []int{8, 13, 18, 23} {
			if raw[i] != '-' {
				return "", false
			}
		}
		raw = raw[:8] + raw[9:13] + raw[14:18] + raw[19:23] + raw[24:]
	}
	if len(raw) != 32 {
		return "", false
	}
	for _, ch := range raw {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return "", false
		}
	}
	return strings.ToLower(raw), true
}

// Validate returns a stable error code for denial. Never derive the authorised
// player UUID from an untrusted runtime request. A missing pre-login UUID does
// not prove the player's identity: the platform MUST authenticate the game
// handshake independently before admitting the connection.
func Validate(observed, authorized string) error {
	expected, valid := CanonicalUUID(authorized)
	if !valid {
		return ErrInvalidAuthorizedUUID
	}
	if strings.TrimSpace(observed) == "" {
		return nil
	}
	actual, valid := CanonicalUUID(observed)
	if !valid {
		return ErrInvalidObservedUUID
	}
	if actual != expected {
		return ErrIdentityMismatch
	}
	return nil
}

// ValidateVerified is used only after a trusted Minecraft online-mode node
// has reported that the observed profile belongs to its authenticated login.
// Unlike the pre-login bridge path, an empty UUID cannot prove that identity.
func ValidateVerified(observed, authorized string) error {
	if strings.TrimSpace(observed) == "" {
		return ErrInvalidObservedUUID
	}
	return Validate(observed, authorized)
}
