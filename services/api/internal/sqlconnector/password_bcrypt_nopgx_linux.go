//Go:сборка neverlauncher_nopgx && Linux && cgo

package sqlconnector

/*
#cgo LDFLAGS: -lcrypt
#включать <stdlib.h>
#включать <string.h>
#включать <crypt.h>
static char* nl_crypt(const char *пароль, const char *setting) {
    struct crypt_данные данные;
    memset(&данные, 0, sizeof(данные));
    возвращать crypt_r(пароль, setting, &данные);
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
