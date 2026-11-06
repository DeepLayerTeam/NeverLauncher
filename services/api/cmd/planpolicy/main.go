// Автономный инструмент оператора подписывает точные JSON-байты политики
// ServerBridge. Никогда не помещайте закрытый ключ в API или репозиторий.
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
	flag.StringVar(&payloadPath, "policy", "", "исходная политика в формате JSON")
	flag.StringVar(&keyPath, "key", "", "offline Ed25519 seed/private key hex file")
	flag.StringVar(&out, "out", "", "выходной JSON с подписанной оболочкой")
	flag.Parse()
	if payloadPath == "" || keyPath == "" || out == "" {
		fmt.Fprintln(os.Stderr, "Использование: planpolicy-02412 -policy policy.json -key private.hex -out signed.json")
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
		panic("Недопустимые параметры политики")
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
		panic("Автономный ключ должен быть 32-байтовым seed Ed25519 или 64-байтовым закрытым ключом")
	}
	if len(raw) > 192*1024 {
		panic("Политика превышает допустимый размер")
	}
	env := planpolicy02412.Envelope{SchemaVersion: "1.0", Payload: base64.StdEncoding.EncodeToString(raw), Signature: hex.EncodeToString(ed25519.Sign(key, append([]byte(planpolicy02412.Domain), raw...)))}
	bytes, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(out, append(bytes, '\n'), 0600); err != nil {
		panic(err)
	}
	fmt.Printf("Подписанная политика: %s\nоткрытый ключ (hex): %x\n", out, key.Public().(ed25519.PublicKey))
}
