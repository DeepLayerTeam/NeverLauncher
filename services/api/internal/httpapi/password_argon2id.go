package httpapi

/*
#cgo linux LDFLAGS: -l:libargon2.so.1
#include <stdlib.h>
#include <stdint.h>

int argon2id_hash_encoded(uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    const void *pwd, size_t pwdlen, const void *salt, size_t saltlen,
    size_t hashlen, char *encoded, size_t encodedlen);

int argon2id_verify(const char *encoded, const void *pwd, size_t pwdlen);
*/
import "C"

import (
	"crypto/rand"
	"fmt"
	"unsafe"
)

const (
	argon2idTimeCost    = 3
	argon2idMemoryKiB   = 64 * 1024
	argon2idParallelism = 1
	argon2idSaltLength  = 16
	argon2idHashLength  = 32
	argon2idEncodedMax  = 256
)

func hashPasswordArgon2id(password string) (string, error) {
	salt := make([]byte, argon2idSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("не удалось создать salt для Argon2id: %w", err)
	}

	passwordBytes := []byte(password)
	passwordPtr := unsafe.Pointer(nil)
	if len(passwordBytes) > 0 {
		passwordPtr = C.CBytes(passwordBytes)
		defer C.free(passwordPtr)
	}

	saltPtr := C.CBytes(salt)
	defer C.free(saltPtr)

	encoded := (*C.char)(C.malloc(C.size_t(argon2idEncodedMax)))
	if encoded == nil {
		return "", fmt.Errorf("не удалось выделить память для Argon2id-хеша")
	}
	defer C.free(unsafe.Pointer(encoded))

	result := C.argon2id_hash_encoded(
		C.uint32_t(argon2idTimeCost),
		C.uint32_t(argon2idMemoryKiB),
		C.uint32_t(argon2idParallelism),
		passwordPtr,
		C.size_t(len(passwordBytes)),
		saltPtr,
		C.size_t(len(salt)),
		C.size_t(argon2idHashLength),
		encoded,
		C.size_t(argon2idEncodedMax),
	)
	if result != 0 {
		return "", fmt.Errorf("argon2id_hash_encoded завершился с кодом %d", int(result))
	}
	return C.GoString(encoded), nil
}

func verifyPasswordArgon2id(password, encoded string) bool {
	encodedC := C.CString(encoded)
	defer C.free(unsafe.Pointer(encodedC))

	passwordBytes := []byte(password)
	passwordPtr := unsafe.Pointer(nil)
	if len(passwordBytes) > 0 {
		passwordPtr = C.CBytes(passwordBytes)
		defer C.free(passwordPtr)
	}

	return C.argon2id_verify(encodedC, passwordPtr, C.size_t(len(passwordBytes))) == 0
}
