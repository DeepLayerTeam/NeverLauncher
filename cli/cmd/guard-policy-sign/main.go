// Утилита guard-policy-sign создаёт офлайн-пару ключей Ed25519 или подписывает проверенную политику
// совместимости Guard. Закрытые ключи никогда не должны попадать в корневой каталог клиента.
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
	mode := flag.String("mode", "sign", "sign, keygen, revoke или rollback")
	current := flag.String("current", "", "Текущий подписанный контейнер политики для revoke/rollback")
	previous := flag.String("previous", "", "Предыдущий подписанный контейнер политики для rollback")
	revokeDigest := flag.String("revoke-digest", "", "Хеши SHA-256 через запятую")
	revokeTransform := flag.String("revoke-transform", "", "Идентификаторы преобразований через запятую")
	policy := flag.String("policy", "", "Исходный JSON-файл политики")
	key := flag.String("private-key", "", "Внешний файл приватного ключа Ed25519 в hex")
	public := flag.String("public-key", "", "Внешний файл для сохранения публичного ключа Ed25519 в hex (keygen)")
	out := flag.String("out", "", "Выходной подписанный контейнер")
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
		err = errors.New("Неизвестное значение параметра --mode")
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
		return errors.New("Необходимо указать оба параметра: --private-key и --public-key")
	}
	// Вызывающая сторона должна выбрать внешний каталог секретов, управляемый оператором.
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
		return errors.New("Необходимо указать --policy, --private-key и --out")
	}
	st, err := os.Lstat(policy)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > 192*1024 {
		return errors.New("Недопустимый исходный файл политики")
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
		return errors.New("Неожиданные данные после значения JSON")
	}
	var version string
	if err = json.Unmarshal(object["schemaVersion"], &version); err != nil || version != schema {
		return errors.New("Неожиданная схема политики")
	}
	sk, err := os.Lstat(key)
	if err != nil {
		return err
	}
	if !sk.Mode().IsRegular() || sk.Size() > 512 {
		return errors.New("Недопустимый файл закрытого ключа")
	}
	rawKey, err := os.ReadFile(key)
	if err != nil {
		return err
	}
	private, err := hex.DecodeString(strings.TrimSpace(string(rawKey)))
	if err != nil || len(private) != ed25519.PrivateKeySize {
		return errors.New("Закрытый ключ должен быть 64-байтовым шестнадцатеричным значением Ed25519 seed+public")
	}
	derived := ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])
	if !bytes.Equal(derived, private) {
		return errors.New("Части закрытого ключа не согласованы")
	}
	signature := ed25519.Sign(ed25519.PrivateKey(private), append([]byte(domain), payload...))
	encoded, err := json.Marshal(map[string]string{"schemaVersion": schema, "payload": base64.StdEncoding.EncodeToString(payload), "signature": hex.EncodeToString(signature)})
	if err != nil {
		return err
	}
	return writeExclusive(out, append(encoded, '\n'))
}
