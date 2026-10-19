package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/DeepLayerTeam/NeverLauncher/prestarter"
	"os"
)

func main() {
	payload := flag.String("payload", "", "unsigned JSON payload")
	keyPath := flag.String("private-key-file", "", "restricted-permission Ed25519 seed hex file")
	out := flag.String("out", "", "signed JSON output")
	flag.Parse()
	if *payload == "" || *keyPath == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "--payload --private-key-file --out required")
		os.Exit(2)
	}
	st, err := os.Stat(*keyPath)
	if err != nil {
		panic(err)
	}
	if st.Mode().Perm()&0077 != 0 {
		panic("private key file must not be group/world accessible")
	}
	raw, err := os.ReadFile(*keyPath)
	if err != nil {
		panic(err)
	}
	seed, err := hex.DecodeString(string(trimSpace(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		panic("expected hex Ed25519 32-byte seed")
	}
	data, err := os.ReadFile(*payload)
	if err != nil {
		panic(err)
	}
	signed, err := prestarter.SignedEnvelope(data, ed25519.NewKeyFromSeed(seed))
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(*out, append(signed, '\n'), 0600); err != nil {
		panic(err)
	}
}
func trimSpace(s []byte) []byte {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\n' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
