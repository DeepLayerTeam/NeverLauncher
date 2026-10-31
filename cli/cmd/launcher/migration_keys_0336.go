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

// Generates independent Never JWT and manifest keys on the operator host.
// Only a new O_EXCL 0600 file is written; NEVER prints secrets to terminal,
// logs, CLI arguments or API responses. Nothing is deployed automatically.
func generateNeverMigrationKeys0336(path string) (err error) {
	if path == "" {
		return errors.New("generate-keys requires --output /secure/private/key-material.json")
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
	// Path must exist and be a private directory; do not create directories or
	// follow a final symlink. O_EXCL prevents replacing an existing key file.
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if !dir.IsDir() || dir.Mode().Perm()&0077 != 0 {
		return errors.New("key output directory must not grant access to group/others (mode 0700)")
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
	fmt.Fprintln(os.Stderr, "New independent Never keys created in 0600 file; provision via secret manager, never upload this file to Gravit or Never API.")
	return nil
}
