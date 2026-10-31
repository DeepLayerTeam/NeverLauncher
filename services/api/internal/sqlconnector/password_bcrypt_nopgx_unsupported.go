//go:build launcher_nopgx && (!linux || !cgo)

package sqlconnector

func verifyBcryptSystem(secret, encoded string) bool { return false }
