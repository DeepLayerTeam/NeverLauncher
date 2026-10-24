package officialminecraft

// Real Mojang online-mode session validation. This does not impersonate a game
// server: a fresh challenge is made for this test and sent to Mojang's public
// sessionserver. It cannot certify the separate game-client/server handshake.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
)

const sessionServerOrigin = "https://sessionserver.mojang.com"

var (
	ErrOnlineSessionRejected  = errors.New("official online-mode session rejected")
	ErrOnlineIdentityMismatch = errors.New("online-mode session identity mismatch")
)

// SignedServerHash matches Java BigInteger(SHA1(serverId + sharedSecret + DER key)).toString(16).
// This intentionally differs from hex encoding of the raw SHA-1 digest.
func SignedServerHash(serverID string, sharedSecret, derKey []byte) string {
	hash := sha1.New() // SHA-1 is mandated by the Minecraft online-mode protocol.
	_, _ = hash.Write([]byte(serverID))
	_, _ = hash.Write(sharedSecret)
	_, _ = hash.Write(derKey)
	digest := hash.Sum(nil)
	negative := digest[0]&0x80 != 0
	if !negative {
		return new(big.Int).SetBytes(digest).Text(16)
	}
	for i := range digest {
		digest[i] = ^digest[i]
	}
	n := new(big.Int).SetBytes(digest)
	n.Add(n, big.NewInt(1))
	return "-" + n.Text(16)
}

// VerifyOnlineSession checks both sides of Mojang's sessionserver handshake
// with a fresh cryptographic server challenge. It never stores or reports the
// bearer, player's name, plain UUID or session hash. Rate limited: call once.
func (c *Client) VerifyOnlineSession(ctx context.Context, token string, profile Profile) error {
	if !validOfficialSubject(profile.ID, profile.Name) || len(token) == 0 || len(token) > 8192 || strings.TrimSpace(token) != token {
		return ErrOnlineSessionRejected
	}
	// Generate a real RSA public key and shared secret, like the Minecraft login handshake.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("create ephemeral online-mode challenge: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return errors.New("invalid online-mode challenge")
	}
	secret := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return errors.New("invalid online-mode challenge")
	}
	hash := SignedServerHash("", secret, der)
	endpoint := c.sessionserver
	if endpoint == "" {
		endpoint = sessionServerOrigin
	}
	join, err := json.Marshal(map[string]string{"accessToken": token, "selectedProfile": strings.ToLower(profile.ID), "serverId": hash})
	// Sensitive JSON body is not persisted. Erase its mutable backing buffer
	// once the request has finished; Go strings may remain until GC.
	defer func() {
		for i := range join {
			join[i] = 0
		}
	}()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/session/minecraft/join", bytes.NewReader(join))
	if err != nil {
		return errors.New("sessionserver join unavailable")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return errors.New("sessionserver join unavailable")
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 4097))
	closeErr := resp.Body.Close()
	if readErr != nil || closeErr != nil {
		return errors.New("sessionserver join response invalid")
	}
	if resp.StatusCode != http.StatusNoContent {
		return &ServiceError{Status: resp.StatusCode, Code: "online_mode_join_rejected"}
	}

	// Unlike a generic profile query, hasJoined binds this fresh challenge to
	// this username AND the bearer that was just accepted by join.
	query := url.Values{"username": {profile.Name}, "serverId": {hash}}
	verifyReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/session/minecraft/hasJoined?"+query.Encode(), nil)
	if err != nil {
		return ErrOnlineSessionRejected
	}
	verifyReq.Header.Set("Accept", "application/json")
	checked, err := c.http.Do(verifyReq)
	if err != nil {
		return errors.New("sessionserver hasJoined unavailable")
	}
	defer checked.Body.Close()
	if checked.StatusCode != http.StatusOK {
		return &ServiceError{Status: checked.StatusCode, Code: "online_mode_has_joined_rejected"}
	}
	if checked.ContentLength > 64*1024 {
		return ErrOnlineSessionRejected
	}
	b, err := io.ReadAll(io.LimitReader(checked.Body, 64*1024+1))
	if err != nil || len(b) > 64*1024 {
		return ErrOnlineSessionRejected
	}
	var identity struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(b, &identity); err != nil {
		return ErrOnlineSessionRejected
	}
	if !strings.EqualFold(identity.ID, profile.ID) || !strings.EqualFold(identity.Name, profile.Name) || !validOfficialSubject(identity.ID, identity.Name) {
		return ErrOnlineIdentityMismatch
	}
	return nil
}

func validOfficialSubject(id, name string) bool {
	if len(id) != 32 || len(name) < 3 || len(name) > 16 {
		return false
	}
	if _, err := hex.DecodeString(id); err != nil {
		return false
	}
	for _, ch := range name {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_') {
			return false
		}
	}
	return true
}
