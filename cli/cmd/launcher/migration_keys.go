package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Создаёт независимые ключи JWT Launcher и манифеста на хосте оператора. Записывается только новый
// файл O_EXCL с правами 0600; секреты НИКОГДА не выводятся в терминал, журнал, аргументы CLI или
// ответы API. Автоматическое развёртывание не выполняется.
func generateLauncherMigrationKeys0336(path string) (err error) {
	if path == "" {
		return errors.New("generate-keys: требуется «--output /secure/private/key-material.json»")
	}
	var token [32]byte
	var seed [32]byte
	var suffix [8]byte
	if _, err = rand.Read(token[:]); err != nil {
		return err
	}
	if _, err = rand.Read(seed[:]); err != nil {
		return err
	}
	if _, err = rand.Read(suffix[:]); err != nil {
		return err
	}
	kid := "migration-" + hex.EncodeToString(suffix[:])
	pub := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	fp := sha256.Sum256(pub)
	payload := struct {
		JWTKeyID             string            `json:"jwtActiveKid"`
		JWTKeys              map[string]string `json:"jwtKeys"`
		ManifestEd25519Seed  string            `json:"manifestEd25519Seed"`
		ManifestPublicSHA256 string            `json:"manifestPublicSha256"`
	}{JWTKeyID: kid, JWTKeys: map[string]string{kid: hex.EncodeToString(token[:])}, ManifestEd25519Seed: hex.EncodeToString(seed[:]), ManifestPublicSHA256: hex.EncodeToString(fp[:])}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	// Путь должен существовать и указывать на закрытый каталог; не создавайте каталоги и не следуйте
	// конечной символьной ссылке. O_EXCL запрещает замену существующего файла ключа.
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if !dir.IsDir() || dir.Mode().Perm()&0077 != 0 {
		return errors.New("Каталог для сохранения ключей должен иметь права 0700 без доступа для группы и остальных пользователей")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	completed := false
	defer func() {
		if !completed {
			_ = os.Remove(path)
		}
	}()
	if _, err = f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	completed = true
	fmt.Fprintln(os.Stderr, "Новые независимые ключи Launcher созданы в файле с правами 0600; установите их через хранилище секретов и никогда не загружайте этот файл в Gravit или Launcher API.")
	return nil
}
