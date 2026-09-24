package httpapi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

const (
	serverBridgeNodeSignatureScheme0142 = "NeverLauncher-ServerBridge-Node-v1"
	serverBridgeNodeMaxBody0142         = 64 << 10
	serverBridgeNodeClockSkew0142       = 90 * time.Second
	serverBridgeNodeNonceTTL0142        = 3 * time.Minute
)

const (
	nodeIDHeader0142          = "X-NeverLauncher-Node-Id"
	nodeFingerprintHeader0142 = "X-NeverLauncher-Node-Key-Fingerprint"
	nodeTimestampHeader0142   = "X-NeverLauncher-Node-Timestamp"
	nodeNonceHeader0142       = "X-NeverLauncher-Node-Nonce"
	nodeSignatureHeader0142   = "X-NeverLauncher-Node-Signature"
)

type bridgeNodeAuthError0142 struct {
	Status int
	Reason string
}

func (e *bridgeNodeAuthError0142) Error() string { return e.Reason }

func validateBridgeNodeIdentity0142(algorithm, publicKey string) (string, string, string, error) {
	algorithm = strings.ToLower(strings.TrimSpace(algorithm))
	if algorithm == "" {
		algorithm = "ed25519"
	}
	if algorithm != "ed25519" {
		return "", "", "", fmt.Errorf("keyAlgorithm должен быть ed25519")
	}
	publicKey = strings.TrimSpace(publicKey)
	raw, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return "", "", "", fmt.Errorf("publicKey должен быть Ed25519 raw public key (32 bytes) в base64url без padding")
	}
	canonical := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256(raw)
	return algorithm, canonical, hex.EncodeToString(sum[:]), nil
}

func serverBridgeCanonicalRequest0142(r *http.Request, body []byte, nodeID, timestamp, nonce string) string {
	target := r.URL.EscapedPath()
	if target == "" {
		target = "/"
	}
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	bodyHash := sha256.Sum256(body)
	return strings.Join([]string{
		serverBridgeNodeSignatureScheme0142,
		strings.TrimSpace(nodeID),
		strings.ToUpper(r.Method),
		target,
		timestamp,
		nonce,
		hex.EncodeToString(bodyHash[:]),
	}, "\n")
}

func readAndRestoreNodeRequestBody0142(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return []byte{}, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, serverBridgeNodeMaxBody0142+1))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, &bridgeNodeAuthError0142{Status: http.StatusRequestEntityTooLarge, Reason: "serverbridge_node_request_too_large"}
		}
		return nil, err
	}
	if len(body) > serverBridgeNodeMaxBody0142 {
		return nil, &bridgeNodeAuthError0142{Status: http.StatusRequestEntityTooLarge, Reason: "serverbridge_node_request_too_large"}
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

func (b *serverBridgeStore) getNode0142(nodeID string) (bridgeServerRecord, error) {
	nodeID = strings.TrimSpace(nodeID)
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		n, err := backend.GetServerBridgeNode(ctx, nodeID)
		if err != nil {
			return bridgeServerRecord{}, err
		}
		return bridgeServerFromModelV2(n), nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	n, ok := b.servers[nodeID]
	if !ok {
		return bridgeServerRecord{}, repository.ErrNotFound
	}
	return n, nil
}

func (b *serverBridgeStore) consumeNodeNonce0142(node bridgeServerRecord, nonceHash string, now time.Time) (bool, error) {
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		return backend.ConsumeServerBridgeNodeNonce(ctx, node.ID, nonceHash, node.IdentityEpoch, now, now.Add(serverBridgeNodeNonceTTL0142))
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.nodeNonces == nil {
		b.nodeNonces = map[string]time.Time{}
	}
	for key, expires := range b.nodeNonces {
		if !expires.After(now) {
			delete(b.nodeNonces, key)
		}
	}
	key := node.ID + ":" + strconv.FormatInt(node.IdentityEpoch, 10) + ":" + nonceHash
	if expires, ok := b.nodeNonces[key]; ok && expires.After(now) {
		return false, nil
	}
	b.nodeNonces[key] = now.Add(serverBridgeNodeNonceTTL0142)
	return true, nil
}

func (s Server) authenticateBridgeNodeRequest0142(r *http.Request) (bridgeServerRecord, error) {
	body, err := readAndRestoreNodeRequestBody0142(r)
	if err != nil {
		if authErr, ok := err.(*bridgeNodeAuthError0142); ok {
			return bridgeServerRecord{}, authErr
		}
		return bridgeServerRecord{}, &bridgeNodeAuthError0142{Status: http.StatusBadRequest, Reason: "serverbridge_node_body_unreadable"}
	}
	nodeID := strings.TrimSpace(r.Header.Get(nodeIDHeader0142))
	fingerprint := strings.ToLower(strings.TrimSpace(r.Header.Get(nodeFingerprintHeader0142)))
	timestampRaw := strings.TrimSpace(r.Header.Get(nodeTimestampHeader0142))
	nonceRaw := strings.TrimSpace(r.Header.Get(nodeNonceHeader0142))
	signatureRaw := strings.TrimSpace(r.Header.Get(nodeSignatureHeader0142))
	if nodeID == "" || fingerprint == "" || timestampRaw == "" || nonceRaw == "" || signatureRaw == "" {
		return bridgeServerRecord{}, &bridgeNodeAuthError0142{Status: http.StatusUnauthorized, Reason: "serverbridge_node_signature_required"}
	}
	if len(nodeID) > 128 || len(fingerprint) != 64 || len(timestampRaw) > 20 || len(nonceRaw) > 96 || len(signatureRaw) > 128 {
		return bridgeServerRecord{}, &bridgeNodeAuthError0142{Status: http.StatusUnauthorized, Reason: "serverbridge_node_headers_invalid"}
	}
	ts, err := strconv.ParseInt(timestampRaw, 10, 64)
	if err != nil {
		return bridgeServerRecord{}, &bridgeNodeAuthError0142{Status: http.StatusUnauthorized, Reason: "serverbridge_node_timestamp_invalid"}
	}
	now := time.Now().UTC()
	requestTime := time.Unix(ts, 0).UTC()
	if requestTime.Before(now.Add(-serverBridgeNodeClockSkew0142)) || requestTime.After(now.Add(serverBridgeNodeClockSkew0142)) {
		return bridgeServerRecord{}, &bridgeNodeAuthError0142{Status: http.StatusUnauthorized, Reason: "serverbridge_node_timestamp_out_of_window"}
	}
	nonce, err := base64.RawURLEncoding.DecodeString(nonceRaw)
	if err != nil || len(nonce) < 16 || len(nonce) > 64 {
		return bridgeServerRecord{}, &bridgeNodeAuthError0142{Status: http.StatusUnauthorized, Reason: "serverbridge_node_nonce_invalid"}
	}
	sig, err := base64.RawURLEncoding.DecodeString(signatureRaw)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return bridgeServerRecord{}, &bridgeNodeAuthError0142{Status: http.StatusUnauthorized, Reason: "serverbridge_node_signature_invalid"}
	}
	node, err := s.State.ServerBridge.getNode0142(nodeID)
	if err != nil || node.Status != "active" || node.KeyAlgorithm != "ed25519" || node.IdentityEpoch < 1 {
		return bridgeServerRecord{}, &bridgeNodeAuthError0142{Status: http.StatusUnauthorized, Reason: "serverbridge_node_identity_invalid"}
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(node.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return bridgeServerRecord{}, &bridgeNodeAuthError0142{Status: http.StatusUnauthorized, Reason: "serverbridge_node_identity_invalid"}
	}
	actualFingerprint := sha256.Sum256(publicKey)
	actualFingerprintHex := hex.EncodeToString(actualFingerprint[:])
	if len(fingerprint) != len(node.KeyFingerprint) || subtle.ConstantTimeCompare([]byte(fingerprint), []byte(node.KeyFingerprint)) != 1 || subtle.ConstantTimeCompare([]byte(actualFingerprintHex), []byte(node.KeyFingerprint)) != 1 {
		return bridgeServerRecord{}, &bridgeNodeAuthError0142{Status: http.StatusUnauthorized, Reason: "serverbridge_node_fingerprint_mismatch"}
	}
	canonical := serverBridgeCanonicalRequest0142(r, body, nodeID, timestampRaw, nonceRaw)
	if !ed25519.Verify(ed25519.PublicKey(publicKey), []byte(canonical), sig) {
		return bridgeServerRecord{}, &bridgeNodeAuthError0142{Status: http.StatusUnauthorized, Reason: "serverbridge_node_signature_invalid"}
	}
	nonceSum := sha256.Sum256(nonce)
	consumed, err := s.State.ServerBridge.consumeNodeNonce0142(node, hex.EncodeToString(nonceSum[:]), now)
	if err != nil {
		return bridgeServerRecord{}, &bridgeNodeAuthError0142{Status: http.StatusServiceUnavailable, Reason: "serverbridge_node_nonce_store_unavailable"}
	}
	if !consumed {
		return bridgeServerRecord{}, &bridgeNodeAuthError0142{Status: http.StatusConflict, Reason: "serverbridge_node_nonce_replayed"}
	}
	return node, nil
}

func writeBridgeNodeAuthError0142(w http.ResponseWriter, err error) {
	if authErr, ok := err.(*bridgeNodeAuthError0142); ok {
		writeError(w, authErr.Status, authErr.Reason)
		return
	}
	writeError(w, http.StatusUnauthorized, "serverbridge_node_identity_invalid")
}
