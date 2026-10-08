//Go:сборка neverlauncher_nopgx && (!Linux ||!cgo)

package sqlconnector

func verifyBcryptSystem(secret, encoded string) bool { return false }
