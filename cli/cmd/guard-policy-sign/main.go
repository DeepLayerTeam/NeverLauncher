// guard-policy-sign creates an offline Ed25519 key pair or signs a reviewed
// Guard compatibility policy. Private keys must never reach the client root.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const schema = "launcher.guard-compatibility.v1"
const domain = "NeverLauncher-Guard-Compatibility-v1\n"

func main() {
	mode := flag.String("mode", "sign", "sign, keygen, revoke or rollback")
	current := flag.String("current", "", "currently signed policy envelope for revoke/rollback")
	previous := flag.String("previous", "", "previous signed policy envelope for rollback")
	revokeDigest := flag.String("revoke-digest", "", "comma-separated SHA-256 hashes")
	revokeTransform := flag.String("revoke-transform", "", "comma-separated transformation IDs")
	policy := flag.String("policy", "", "source policy JSON")
	key := flag.String("private-key", "", "external hex Ed25519 private key file")
	public := flag.String("public-key", "", "external hex Ed25519 public key output for keygen")
	out := flag.String("out", "", "signed envelope output")
	flag.Parse()
	var err error
	switch *mode {
	case "sign":
		err = sign(*policy, *key, *out)
	case "keygen":
		err = keygen(*key, *public)
	case "revoke", "rollback":
		err = operatorRevise05011(*mode, *current, *previous, *key, *out, *revokeDigest, *revokeTransform, time.Now())
	default:
		err = errors.New("unknown --mode")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "guard-policy-sign:", err)
		os.Exit(1)
	}
}
func writeExclusive(path string, raw []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = file.Write(raw); err != nil {
		file.Close()
		os.Remove(path)
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		os.Remove(path)
		return err
	}
	return file.Close()
}
func keygen(privatePath, publicPath string) error {
	if privatePath == "" || publicPath == "" || privatePath == publicPath {
		return errors.New("separate --private-key and --public-key required")
	}
	// The caller must choose an external, operator-controlled secret directory.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err = writeExclusive(privatePath, []byte(hex.EncodeToString(priv)+"\n")); err != nil {
		return err
	}
	if err = writeExclusive(publicPath, []byte(hex.EncodeToString(pub)+"\n")); err != nil {
		_ = os.Remove(privatePath)
		return err
	}
	return nil
}
func sign(policy, key, out string) error {
	if policy == "" || key == "" || out == "" {
		return errors.New("--policy, --private-key and --out are required")
	}
	st, err := os.Lstat(policy)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > 192*1024 {
		return errors.New("invalid policy source file")
	}
	payload, err := os.ReadFile(policy)
	if err != nil {
		return err
	}
	var object map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(payload))
	if err = dec.Decode(&object); err != nil {
		return err
	}
	var extra any
	if err = dec.Decode(&extra); err != io.EOF {
		return errors.New("unexpected trailing JSON")
	}
	var version string
	if err = json.Unmarshal(object["schemaVersion"], &version); err != nil || version != schema {
		return errors.New("unexpected policy schema")
	}
	sk, err := os.Lstat(key)
	if err != nil {
		return err
	}
	if !sk.Mode().IsRegular() || sk.Size() > 512 {
		return errors.New("invalid private key file")
	}
	rawKey, err := os.ReadFile(key)
	if err != nil {
		return err
	}
	private, err := hex.DecodeString(strings.TrimSpace(string(rawKey)))
	if err != nil || len(private) != ed25519.PrivateKeySize {
		return errors.New("private key must be 64-byte Ed25519 seed+public hex")
	}
	derived := ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])
	if !bytes.Equal(derived, private) {
		return errors.New("private key halves inconsistent")
	}
	signature := ed25519.Sign(ed25519.PrivateKey(private), append([]byte(domain), payload...))
	encoded, err := json.Marshal(map[string]string{"schemaVersion": schema, "payload": base64.StdEncoding.EncodeToString(payload), "signature": hex.EncodeToString(signature)})
	if err != nil {
		return err
	}
	return writeExclusive(out, append(encoded, '\n'))
}
