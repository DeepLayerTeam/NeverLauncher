package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

const serverBridgeJoinTicketVersion0143 = 2

func newServerBridgeJoinTicketID0143() (string, error) {
	buf := make([]byte, 24) // 192 bits; ticket identifiers never fall back to time/predictable entropy.
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("secure join ticket entropy unavailable: %w", err)
	}
	return "jt_" + base64.RawURLEncoding.EncodeToString(buf), nil
}

func bridgeJoinRedemption0143(r *http.Request, server bridgeServerRecord) (model.ServerBridgeJoinRedemption, error) {
	nonceRaw := strings.TrimSpace(r.Header.Get(nodeNonceHeader0142))
	nonce, err := base64.RawURLEncoding.DecodeString(nonceRaw)
	if err != nil || len(nonce) < 16 || len(nonce) > 64 {
		return model.ServerBridgeJoinRedemption{}, fmt.Errorf("serverbridge join redemption nonce invalid")
	}
	nonceSum := sha256.Sum256(nonce)
	if server.ID == "" || server.IdentityEpoch < 1 || len(server.KeyFingerprint) != 64 {
		return model.ServerBridgeJoinRedemption{}, fmt.Errorf("serverbridge node identity unavailable for ticket redemption")
	}
	return model.ServerBridgeJoinRedemption{
		NodeID:         server.ID,
		IdentityEpoch:  server.IdentityEpoch,
		KeyFingerprint: strings.ToLower(server.KeyFingerprint),
		NonceHash:      hex.EncodeToString(nonceSum[:]),
		RemoteIP:       clientIP(r),
	}, nil
}
