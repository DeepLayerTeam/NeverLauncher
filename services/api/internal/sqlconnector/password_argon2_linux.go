//go:build linux && cgo

package sqlconnector

/*
#cgo LDFLAGS: -l:libargon2.so.1
#include <stdlib.h>
#include <stdint.h>
int argon2id_verify(const char *encoded, const void *pwd, size_t pwdlen);
*/
import "C"

import "unsafe"

func argon2idAvailable() bool { return true }

func verifyArgon2idSystem(secret, encoded string) bool {
	encodedC := C.CString(encoded)
	defer C.free(unsafe.Pointer(encodedC))
	passwordBytes := []byte(secret)
	var passwordPtr unsafe.Pointer
	if len(passwordBytes) > 0 {
		passwordPtr = C.CBytes(passwordBytes)
		defer C.free(passwordPtr)
	}
	return C.argon2id_verify(encodedC, passwordPtr, C.size_t(len(passwordBytes))) == 0
}
