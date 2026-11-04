// Offline operator tool: signs exact ServerBridge policy JSON bytes. Never put
// the private key in the API or the repository.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"gitflic.ru/skif4er/launcher/services/api/internal/planpolicy02412"
	"os"
	"strings"
)

func main() {
	var payloadPath, keyPath, out string
	flag.StringVar(&payloadPath, "policy", "", "raw JSON policy")
	flag.StringVar(&keyPath, "key", "", "offline Ed25519 seed/private key hex file")
	flag.StringVar(&out, "out", "", "output signed envelope JSON")
	flag.Parse()
	if payloadPath == "" || keyPath == "" || out == "" {
		fmt.Fprintln(os.Stderr, "usage: planpolicy-02412 -policy policy.json -key private.hex -out signed.json")
		os.Exit(2)
	}
	raw, err := os.ReadFile(payloadPath)
	if err != nil {
		panic(err)
	}
	var p planpolicy02412.Policy
	if err = json.Unmarshal(raw, &p); err != nil {
		panic(err)
	}
	if p.SchemaVersion != "1.0" || !p.RequireContinuousGuard || len(p.AllowedPlans) == 0 {
		panic("invalid policy parameters")
	}
	privBytes, err := os.ReadFile(keyPath)
	if err != nil {
		panic(err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(privBytes)))
	if err != nil {
		panic(err)
	}
	var key ed25519.PrivateKey
	switch len(seed) {
	case ed25519.SeedSize:
		key = ed25519.NewKeyFromSeed(seed)
	case ed25519.PrivateKeySize:
		key = ed25519.PrivateKey(seed)
	default:
		panic("offline key must be 32-byte Ed25519 seed or 64-byte private key")
	}
	if len(raw) > 192*1024 {
		panic("policy too large")
	}
	env := planpolicy02412.Envelope{SchemaVersion: "1.0", Payload: base64.StdEncoding.EncodeToString(raw), Signature: hex.EncodeToString(ed25519.Sign(key, append([]byte(planpolicy02412.Domain), raw...)))}
	bytes, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(out, append(bytes, '\n'), 0600); err != nil {
		panic(err)
	}
	fmt.Printf("signed policy: %s\npublic-key-hex: %x\n", out, key.Public().(ed25519.PublicKey))
}
