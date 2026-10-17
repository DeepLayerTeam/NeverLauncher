package repository

import "unicode/utf8"

// normalizeServerBridgeControlFailure bounds persisted PostgreSQL text to 1024
// UTF-8 bytes, preserving complete runes. Normalize before both the first ACK
// and subsequent idempotent retries so identical requests compare identically.
func normalizeServerBridgeControlFailure(failure string) string {
	if len(failure) <= 1024 {
		return failure
	}
	cut := 1024
	for cut > 0 && !utf8.RuneStart(failure[cut]) {
		cut--
	}
	return failure[:cut]
}
