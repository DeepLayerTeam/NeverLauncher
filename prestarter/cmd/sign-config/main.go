package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/DeepLayerTeam/Launcher/prestarter"
	"os"
)

func main() {
	payload := flag.String("payload", "", "Неподписанные данные JSON")
	keyPath := flag.String("private-key-file", "", "Файл Ed25519 seed в шестнадцатеричном формате с ограниченными правами доступа")
	out := flag.String("out", "", "Выходной подписанный JSON")
	policyPath := flag.String("trust-policy", "", "Файл делегированной политики доверия, подписанной корневым ключом")
	rootKey := flag.String("root-public-key", "", "Предварительно установленный публичный корневой ключ Ed25519 (64 hex)")
	keyID := flag.String("key-id", "", "Идентификатор делегированного ключа подписи bootstrap")
	flag.Parse()
	if *payload == "" || *keyPath == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "Необходимо указать --payload, --private-key-file и --out")
		os.Exit(2)
	}
	st, err := os.Stat(*keyPath)
	if err != nil {
		panic(err)
	}
	if st.Mode().Perm()&0077 != 0 {
		panic("Файл приватного ключа не должен быть доступен группе или другим пользователям")
	}
	raw, err := os.ReadFile(*keyPath)
	if err != nil {
		panic(err)
	}
	seed, err := hex.DecodeString(string(trimSpace(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		panic("Ожидается 32-байтовое начальное значение Ed25519 в шестнадцатеричном формате-формате")
	}
	data, err := os.ReadFile(*payload)
	if err != nil {
		panic(err)
	}
	var signed []byte
	if *policyPath != "" {
		if *rootKey == "" || *keyID == "" {
			panic("Для делегированной подписи необходимы --root-public-key и --key-id")
		}
		policy, e := os.ReadFile(*policyPath)
		if e != nil {
			panic(e)
		}
		signed, err = prestarter.SignedEnvelopeDelegated(data, ed25519.NewKeyFromSeed(seed), policy, *rootKey, *keyID)
	} else {
		if *rootKey != "" || *keyID != "" {
			panic("Для параметров делегирования необходимо указать --trust-policy")
		}
		signed, err = prestarter.SignedEnvelope(data, ed25519.NewKeyFromSeed(seed))
	}
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
