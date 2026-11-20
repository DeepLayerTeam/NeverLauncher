//go:build windows

package yggdrasiltexture

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"gitflic.ru/skif4er/launcher/services/api/internal/privatefile"
)

// POSIX mode bits do not represent NTFS ACL permissions.  A Windows signing
// key with an Everyone-read ACE must fail closed, even if it is a valid RSA key.
func TestYggdrasilRejectsPublicWindowsACL0256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "yggdrasil.pem")
	payload := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := privatefile.Restrict(path, false); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err != nil {
		t.Fatalf("Защищённый файл ключа ошибочно отклонён: %v", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	// Give the creator full control while granting Everyone read permission.
	// This specifically tests that the ACL, not os.FileMode.Perm, is checked.
	sddl := "D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;GR;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("Ключ с Everyone-read ACL ошибочно разрешён для подписи Yggdrasil")
	}
}
