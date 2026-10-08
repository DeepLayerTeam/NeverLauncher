//go:build neverlauncher_nopgx && linux && cgo

package sqlconnector

/*
#cgo LDFLAGS: -lcrypt
#include <stdlib.h>
#include <string.h>
#include <crypt.h>
static char* nl_crypt(const char *password, const char *setting) {
    struct crypt_data data;
    memset(&data, 0, sizeof(data));
    return crypt_r(password, setting, &data);
}
*/
import "C"

import (
	"crypto/subtle"
	"unsafe"
)

func verifyBcryptSystem(secret, encoded string) bool {
	secretC := C.CString(secret)
	encodedC := C.CString(encoded)
	defer C.free(unsafe.Pointer(secretC))
	defer C.free(unsafe.Pointer(encodedC))
	result := C.nl_crypt(secretC, encodedC)
	if result == nil {
		return false
	}
	actual := []byte(C.GoString(result))
	expected := []byte(encoded)
	return len(actual) == len(expected) && subtle.ConstantTimeCompare(actual, expected) == 1
}
