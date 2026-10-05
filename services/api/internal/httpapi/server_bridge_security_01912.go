package httpapi

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

const (
	serverBridgeV3SigningDomain01912 = "NeverLauncher-ServerBridge-Protocol-v3"
	serverBridgeSecurityProfile01912 = "serverbridge3-security-01912"

	serverBridgeFeatureV3SigningDomain01912     = "security.protocol-v3-signing-domain"
	serverBridgeFeatureDowngradeProtection01912 = "security.capability-downgrade-protection"
	serverBridgeFeatureCommandSignatures01912   = "security.command-signatures-v3"
	serverBridgeFeatureEventSignatures01912     = "security.event-signatures-v3"
	serverBridgeFeatureRuntimeBinding01912      = "security.runtime-instance-binding-v3"
	serverBridgeFeatureOnlineKeyRotation01912   = "security.online-key-rotation-v1"
)

var serverBridgeSecurityRequiredFeatures01912 = []string{
	serverBridgeFeatureV3SigningDomain01912,
	serverBridgeFeatureDowngradeProtection01912,
	serverBridgeFeatureCommandSignatures01912,
	serverBridgeFeatureEventSignatures01912,
	serverBridgeFeatureRuntimeBinding01912,
	serverBridgeFeatureOnlineKeyRotation01912,
}

func serverBridgeSecurityCapabilityDigest01912(features []string) string {
	allowed := make(map[string]struct{}, len(serverBridgeSecurityRequiredFeatures01912))
	for _, feature := range serverBridgeSecurityRequiredFeatures01912 {
		allowed[feature] = struct{}{}
	}
	selected := make([]string, 0, len(serverBridgeSecurityRequiredFeatures01912))
	for _, feature := range normalizeBridgeFeatures0191(features) {
		if _, ok := allowed[feature]; ok {
			selected = append(selected, feature)
		}
	}
	sort.Strings(selected)
	canonical := strings.Join([]string{
		serverBridgeV3SigningDomain01912,
		"capabilities",
		strconv.Itoa(serverBridgeProtocolV3),
		serverBridgeSecurityProfile01912,
		strings.Join(selected, "\n"),
	}, "\n")
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

func serverBridgeExpectedSecurityCapabilityDigest01912() string {
	return serverBridgeSecurityCapabilityDigest01912(serverBridgeSecurityRequiredFeatures01912)
}

func serverBridgeV3SecurityEnabled01912(features []string) bool {
	set := make(map[string]struct{}, len(features))
	for _, feature := range normalizeBridgeFeatures0191(features) {
		set[feature] = struct{}{}
	}
	for _, feature := range serverBridgeSecurityRequiredFeatures01912 {
		if _, ok := set[feature]; !ok {
			return false
		}
	}
	return true
}

func serverBridgeSecurityFeaturesExact01912(features []string) bool {
	normalized := normalizeBridgeFeatures0191(features)
	return len(normalized) == len(serverBridgeSecurityRequiredFeatures01912) && serverBridgeV3SecurityEnabled01912(normalized)
}

func validateServerBridgeSecurityEnvelope01912(r *http.Request, protocolVersion int, features []string) (bool, string) {
	profile := strings.TrimSpace(r.Header.Get(nodeSecurityProfile01912))
	if profile == "" {
		return false, ""
	}
	if profile != serverBridgeSecurityProfile01912 || protocolVersion != serverBridgeProtocolV3 {
		return false, "serverbridge_security_profile_unsupported"
	}
	if !serverBridgeV3SecurityEnabled01912(features) {
		return false, "serverbridge_capability_downgrade_detected"
	}
	return true, ""
}

func serverBridgeBoundRuntimeHeader01912(r *http.Request) string {
	return strings.ToLower(strings.TrimSpace(r.Header.Get(nodeRuntimeIDHeader01912)))
}

func serverBridgeCapabilityCanonical01912(capabilityDigest, activeFingerprint, previousFingerprint string) string {
	return strings.Join([]string{
		serverBridgeV3SigningDomain01912,
		"capabilities",
		strconv.Itoa(serverBridgeProtocolV3),
		serverBridgeSecurityProfile01912,
		strings.ToLower(strings.TrimSpace(capabilityDigest)),
		strings.ToLower(strings.TrimSpace(activeFingerprint)),
		strings.ToLower(strings.TrimSpace(previousFingerprint)),
	}, "\n")
}

func serverBridgeNodeRequestCanonical01912(r *http.Request, body []byte, nodeID, fingerprint, timestamp, nonce, runtimeID, capabilityDigest string) string {
	target := r.URL.EscapedPath()
	if target == "" {
		target = "/"
	}
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	bodyHash := sha256.Sum256(body)
	enc := func(value string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(strings.TrimSpace(value)))
	}
	return strings.Join([]string{
		serverBridgeV3SigningDomain01912,
		"node-request",
		strconv.Itoa(serverBridgeProtocolV3),
		serverBridgeSecurityProfile01912,
		enc(nodeID),
		strings.ToLower(strings.TrimSpace(fingerprint)),
		strings.ToUpper(strings.TrimSpace(r.Method)),
		target,
		timestamp,
		nonce,
		strings.ToLower(strings.TrimSpace(runtimeID)),
		strings.ToLower(strings.TrimSpace(capabilityDigest)),
		hex.EncodeToString(bodyHash[:]),
	}, "\n")
}

func serverBridgeEventCanonical01912(serverID, eventID, runtimeID, keyFingerprint, capabilityDigest string, sequence int64, eventType string, occurredAt int64, payloadSHA string) string {
	enc := func(value string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(strings.TrimSpace(value)))
	}
	return strings.Join([]string{
		serverBridgeV3SigningDomain01912,
		"event",
		strconv.Itoa(serverBridgeProtocolV3),
		serverBridgeSecurityProfile01912,
		enc(serverID),
		strings.TrimSpace(eventID),
		strings.ToLower(strings.TrimSpace(runtimeID)),
		strings.ToLower(strings.TrimSpace(keyFingerprint)),
		strings.ToLower(strings.TrimSpace(capabilityDigest)),
		strconv.FormatInt(sequence, 10),
		strconv.FormatInt(occurredAt, 10),
		enc(eventType),
		strings.ToLower(strings.TrimSpace(payloadSHA)),
	}, "\n")
}

func serverBridgeControlCanonical01912(serverID, commandID, runtimeID, kind, payloadSHA, channelID, leaseToken, capabilityDigest, signerFingerprint string, identityEpoch, runtimeEpoch, deliverySequence int64, attempt int, issuedAt, expiresAt int64) string {
	enc := func(value string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(strings.TrimSpace(value)))
	}
	return strings.Join([]string{
		serverBridgeV3SigningDomain01912,
		"command",
		strconv.Itoa(serverBridgeProtocolV3),
		serverBridgeSecurityProfile01912,
		enc(serverID),
		enc(commandID),
		strconv.FormatInt(identityEpoch, 10),
		strconv.FormatInt(runtimeEpoch, 10),
		strings.ToLower(strings.TrimSpace(runtimeID)),
		strings.ToLower(strings.TrimSpace(capabilityDigest)),
		enc(kind),
		strings.ToLower(strings.TrimSpace(payloadSHA)),
		strconv.FormatInt(deliverySequence, 10),
		enc(channelID),
		enc(leaseToken),
		strconv.Itoa(attempt),
		strconv.FormatInt(issuedAt, 10),
		strconv.FormatInt(expiresAt, 10),
		strings.ToLower(strings.TrimSpace(signerFingerprint)),
	}, "\n")
}

type serverBridgeSigningKey01912 struct {
	PrivateKey  ed25519.PrivateKey
	PublicKey   ed25519.PublicKey
	PublicB64   string
	Fingerprint string
}

func serverBridgeSigningKeyFromPrivate01912(privateKey ed25519.PrivateKey) serverBridgeSigningKey01912 {
	publicKey := privateKey.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(publicKey)
	return serverBridgeSigningKey01912{
		PrivateKey:  privateKey,
		PublicKey:   publicKey,
		PublicB64:   base64.RawURLEncoding.EncodeToString(publicKey),
		Fingerprint: hex.EncodeToString(sum[:]),
	}
}

func serverBridgeSigningKeyFromSeed01912(seedHex string) (serverBridgeSigningKey01912, error) {
	seed, err := hex.DecodeString(strings.TrimSpace(seedHex))
	if err != nil || len(seed) != ed25519.SeedSize {
		return serverBridgeSigningKey01912{}, fmt.Errorf("ServerBridge previous control signing key must be a 32-byte Ed25519 seed in hex")
	}
	return serverBridgeSigningKeyFromPrivate01912(ed25519.NewKeyFromSeed(seed)), nil
}

func (s Server) serverBridgeSigningKeys01912() (serverBridgeSigningKey01912, *serverBridgeSigningKey01912, error) {
	privateKey, err := s.serverBridgeControlSigningPrivateKey0195()
	if err != nil {
		return serverBridgeSigningKey01912{}, nil, err
	}
	active := serverBridgeSigningKeyFromPrivate01912(privateKey)
	previousRaw := strings.TrimSpace(s.Config.ServerBridgeControlPreviousSigningPrivateKey)
	if previousRaw == "" {
		return active, nil, nil
	}
	previous, err := serverBridgeSigningKeyFromSeed01912(previousRaw)
	if err != nil {
		return serverBridgeSigningKey01912{}, nil, err
	}
	if previous.Fingerprint == active.Fingerprint {
		return serverBridgeSigningKey01912{}, nil, fmt.Errorf("ServerBridge active and previous control signing keys must differ")
	}
	return active, &previous, nil
}
