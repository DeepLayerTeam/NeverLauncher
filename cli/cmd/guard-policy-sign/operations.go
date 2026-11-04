package main

// Offline operator-side policy lifecycle. The signing key is never copied to
// any Launcher/Guard client. Rollback means a signed NEW policy epoch that
// restores an earlier approved configuration; it never lowers the client floor.
import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"
)

type signedPolicy05011 struct {
	Schema    string `json:"schemaVersion"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
type policyContent05011 struct {
	Schema                 string            `json:"schemaVersion"`
	ProjectID              string            `json:"projectId"`
	Minecraft              string            `json:"minecraft"`
	Loader                 string            `json:"loader"`
	Epoch                  uint64            `json:"epoch"`
	IssuedAt               int64             `json:"issuedAt"`
	ExpiresAt              int64             `json:"expiresAt"`
	Artifacts              []json.RawMessage `json:"artifacts"`
	Transformations        []json.RawMessage `json:"transformations"`
	RevokedDigests         []string          `json:"revokedDigests"`
	RevokedTransformations []string          `json:"revokedTransformations"`
	LoaderClassBytes       []json.RawMessage `json:"loaderClassBytes,omitempty"`
	ExternalNativeModules  []json.RawMessage `json:"externalNativeModules,omitempty"`
}

func operatorRead05011(path string, cap int64) ([]byte, error) {
	if path == "" {
		return nil, errors.New("signed policy file required")
	}
	stat, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() || stat.Size() == 0 || stat.Size() > cap {
		return nil, errors.New("unsafe signed policy input")
	}
	return os.ReadFile(path)
}
func operatorKey05011(key string) (ed25519.PrivateKey, error) {
	raw, err := operatorRead05011(key, 512)
	if err != nil {
		return nil, err
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key")
	}
	derived := ed25519.NewKeyFromSeed(decoded[:ed25519.SeedSize])
	if !bytes.Equal(derived, decoded) {
		return nil, errors.New("private key halves inconsistent")
	}
	return ed25519.PrivateKey(decoded), nil
}
func operatorParse05011(file string, priv ed25519.PrivateKey) (policyContent05011, error) {
	var result policyContent05011
	raw, err := operatorRead05011(file, 256*1024)
	if err != nil {
		return result, err
	}
	var env signedPolicy05011
	if err = decodeStrict05011(raw, &env); err != nil {
		return result, err
	}
	if env.Schema != schema {
		return result, errors.New("policy envelope schema mismatch")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(env.Payload)
	if err != nil || len(payload) == 0 || len(payload) > 192*1024 {
		return result, errors.New("invalid policy payload")
	}
	signature, err := hex.DecodeString(env.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return result, errors.New("invalid signature length")
	}
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), append([]byte(domain), payload...), signature) {
		return result, errors.New("signed policy failed verification with operator key")
	}
	if err = decodeStrict05011(payload, &result); err != nil {
		return result, err
	}
	if result.Schema != schema || result.Epoch == 0 || result.ProjectID == "" || result.Minecraft == "" || result.Loader == "" || result.ExpiresAt <= result.IssuedAt {
		return result, errors.New("invalid signed policy scope/epoch/timestamps")
	}
	return result, nil
}
func decodeStrict05011(raw []byte, dest any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return errors.New("trailing JSON")
}
func mergeRevocations05011(current, previous []string) ([]string, error) {
	set := map[string]bool{}
	out := make([]string, 0, len(current)+len(previous))
	for _, s := range append(append([]string{}, current...), previous...) {
		if s == "" || len(s) > 256 || strings.ContainsAny(s, "\x00\r\n") {
			return nil, errors.New("invalid revocation entry")
		}
		if !set[s] {
			out = append(out, s)
			set[s] = true
		}
	}
	if len(out) > 4096 {
		return nil, errors.New("revocation list too long")
	}
	return out, nil
}
func verifyDigest05011(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
func operatorRevise05011(mode, currentFile, previousFile, keyFile, outFile, digests, transforms string, now time.Time) error {
	if mode != "revoke" && mode != "rollback" {
		return errors.New("expected revoke or rollback")
	}
	if outFile == "" {
		return errors.New("--out required")
	}
	private, err := operatorKey05011(keyFile)
	if err != nil {
		return err
	}
	current, err := operatorParse05011(currentFile, private)
	if err != nil {
		return err
	}
	if current.Epoch == math.MaxUint64 {
		return errors.New("epoch exhausted")
	}
	next := current
	if mode == "rollback" {
		if previousFile == "" {
			return errors.New("--previous signed policy required")
		}
		previous, err := operatorParse05011(previousFile, private)
		if err != nil {
			return err
		}
		if previous.Epoch >= current.Epoch {
			return errors.New("rollback source must be older")
		}
		if previous.ProjectID != current.ProjectID || previous.Minecraft != current.Minecraft || !strings.EqualFold(previous.Loader, current.Loader) {
			return errors.New("rollback policy scope differs")
		}
		next = previous
	} else if strings.TrimSpace(digests) == "" && strings.TrimSpace(transforms) == "" {
		return errors.New("at least one revocation required")
	}
	next.Epoch = current.Epoch + 1
	next.IssuedAt = now.Unix()
	next.ExpiresAt = now.Add(7 * 24 * time.Hour).Unix()
	newDigests := []string{}
	for _, s := range strings.Split(digests, ",") {
		if s == "" {
			continue
		}
		s = strings.TrimSpace(s)
		if !verifyDigest05011(s) {
			return errors.New("revoke digest must be lowercase SHA-256")
		}
		newDigests = append(newDigests, s)
	}
	newTrans := []string{}
	for _, s := range strings.Split(transforms, ",") {
		if s == "" {
			continue
		}
		s = strings.TrimSpace(s)
		if s == "" {
			return errors.New("empty transformation")
		}
		newTrans = append(newTrans, s)
	}
	next.RevokedDigests, err = mergeRevocations05011(current.RevokedDigests, append(next.RevokedDigests, newDigests...))
	if err != nil {
		return err
	}
	next.RevokedTransformations, err = mergeRevocations05011(current.RevokedTransformations, append(next.RevokedTransformations, newTrans...))
	if err != nil {
		return err
	}
	// Existing schema fields are all retained; operators cannot clear older revocations.
	payload, err := json.Marshal(next)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(private, append([]byte(domain), payload...))
	envelope, err := json.Marshal(signedPolicy05011{Schema: schema, Payload: base64.StdEncoding.EncodeToString(payload), Signature: hex.EncodeToString(sig)})
	if err != nil {
		return err
	}
	if err = writeExclusive(outFile, append(envelope, '\n')); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "signed Guard %s epoch %d (previous %d), revoked digests=%d transforms=%d\n", mode, next.Epoch, current.Epoch, len(next.RevokedDigests), len(next.RevokedTransformations))
	return nil
}
