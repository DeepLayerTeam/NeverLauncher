// Пакет yggdrasiltexture подписывает свойства текстур authlib-injector с помощью
// протокольную подпись RSA PKCS#1 v1.5 / SHA-1, вместе с Ed25519 манифеста.
package yggdrasiltexture

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Signer неизменяем; создавайте его при запуске и перезапускайте API для ротации ключа.
type Signer struct {
	key       *rsa.PrivateKey
	PublicPEM string
}

func ParsePrivateKey(pemBytes []byte) (*Signer, error) {
	block, remainder := pem.Decode(pemBytes)
	if block == nil || len(strings.TrimSpace(string(remainder))) != 0 || len(block.Headers) != 0 {
		return nil, errors.New("Требуется: «ровно один незашифрованный закрытый ключ PEM»")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		value, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = value
	case "PRIVATE KEY":
		value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		parsed, ok := value.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("Для Yggdrasil требуется: RSA закрытый ключ")
		}
		key = parsed
	default:
		return nil, errors.New("Не поддерживается: ключ подписи PEM тип")
	}
	if key.N.BitLen() < 2048 {
		return nil, errors.New("RSA key: требуется «не менее 2048 бит»")
	}
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("Некорректное значение: RSA ключ подписи: %w", err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Signer{key: key, PublicPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))}, nil
}

func LoadFile(path string) (*Signer, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("Файл RSA-ключа подписи Yggdrasil не настроен")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("Ошибка чтения метаданных RSA-ключа: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("Требуется обычный файл: RSA ключ подписи")
	}
	if info.Size() > 32*1024 {
		return nil, errors.New("Превышен допустимый размер: RSA ключ подписи файл")
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("«файл ключа подписи RSA»: запрещено «быть доступным группе или посторонним пользователям (chmod 600)»")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(content)
}

func (s *Signer) SignValue(value string) (string, error) {
	digest := sha1.Sum([]byte(value))
	signed, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA1, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signed), nil
}
func (s *Signer) VerifyValue(value, signature string) error {
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	digest := sha1.Sum([]byte(value))
	return rsa.VerifyPKCS1v15(&s.key.PublicKey, crypto.SHA1, digest[:], raw)
}

var ephemeral struct {
	once   sync.Once
	signer *Signer
	err    error
}

// Ключ локального процесса только для разработки: в промышленной среде нужен постоянный ключ на диске.
func DevelopmentSigner() (*Signer, error) {
	ephemeral.once.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			ephemeral.err = err
			return
		}
		pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			ephemeral.err = err
			return
		}
		ephemeral.signer = &Signer{key: k, PublicPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))}
	})
	return ephemeral.signer, ephemeral.err
}
