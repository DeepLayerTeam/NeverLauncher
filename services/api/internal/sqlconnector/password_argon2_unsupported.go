//go:build !linux || !cgo

package sqlconnector

func argon2idAvailable() bool { return false }

func verifyArgon2idSystem(secret, encoded string) bool { return false }
