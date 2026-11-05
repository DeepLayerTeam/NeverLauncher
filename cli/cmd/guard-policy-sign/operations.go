package main

// Жизненный цикл политики на стороне оператора без подключения к сети. Ключ подписи никогда не копируется
// на клиент Launcher/Guard. Откат означает НОВУЮ подписанную эпоху политики, которая восстанавливает
// ранее утверждённые настройки; минимальная допустимая эпоха клиента при этом не понижается.
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
		return nil, errors.New("Необходим файл подписанной политики")
	}
	stat, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() || stat.Size() == 0 || stat.Size() > cap {
		return nil, errors.New("Небезопасные входные данные подписанной политики")
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
		return nil, errors.New("Недопустимый закрытый ключ Ed25519")
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
		return result, errors.New("Несовпадение схемы оболочки политики")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(env.Payload)
	if err != nil || len(payload) == 0 || len(payload) > 192*1024 {
		return result, errors.New("Недопустимые данные политики")
	}
	signature, err := hex.DecodeString(env.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return result, errors.New("Недопустимая длина подписи")
	}
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), append([]byte(domain), payload...), signature) {
		return result, errors.New("Подпись политики не прошла проверку ключом оператора")
	}
	if err = decodeStrict05011(payload, &result); err != nil {
		return result, err
	}
	if result.Schema != schema || result.Epoch == 0 || result.ProjectID == "" || result.Minecraft == "" || result.Loader == "" || result.ExpiresAt <= result.IssuedAt {
		return result, errors.New("Недопустимая область действия, эпоха или временные метки подписанной политики")
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
	return errors.New("Лишние данные после JSON")
}
func mergeRevocations05011(current, previous []string) ([]string, error) {
	set := map[string]bool{}
	out := make([]string, 0, len(current)+len(previous))
	for _, s := range append(append([]string{}, current...), previous...) {
		if s == "" || len(s) > 256 || strings.ContainsAny(s, "\x00\r\n") {
			return nil, errors.New("Недопустимая запись об отзыве")
		}
		if !set[s] {
			out = append(out, s)
			set[s] = true
		}
	}
	if len(out) > 4096 {
		return nil, errors.New("Список отзывов слишком длинный")
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
		return errors.New("Ожидалась операция revoke или rollback")
	}
	if outFile == "" {
		return errors.New("Необходимо указать --out")
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
		return errors.New("Исчерпан диапазон значений эпохи")
	}
	next := current
	if mode == "rollback" {
		if previousFile == "" {
			return errors.New("Требуется предыдущая подписанная политика через --previous")
		}
		previous, err := operatorParse05011(previousFile, private)
		if err != nil {
			return err
		}
		if previous.Epoch >= current.Epoch {
			return errors.New("Исходная версия для отката должна быть более ранней")
		}
		if previous.ProjectID != current.ProjectID || previous.Minecraft != current.Minecraft || !strings.EqualFold(previous.Loader, current.Loader) {
			return errors.New("Область действия политики отката отличается")
		}
		next = previous
	} else if strings.TrimSpace(digests) == "" && strings.TrimSpace(transforms) == "" {
		return errors.New("Требуется хотя бы одна запись об отзыве")
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
			return errors.New("Хеш отзыва должен быть SHA-256 в нижнем регистре")
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
			return errors.New("Пустое преобразование")
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
	// Все существующие поля схемы сохраняются; оператор не может очистить старые отзывы.
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
