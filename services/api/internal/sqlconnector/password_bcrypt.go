//go:build !neverlauncher_nopgx

package sqlconnector

import "golang.org/x/crypto/bcrypt"

func verifyBcryptSystem(secret, encoded string) bool {
	return bcrypt.CompareHashAndPassword([]byte(encoded), []byte(secret)) == nil
}
