package extensionbroker

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScopedFilesystemBrokers03110(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := Write(root, "nested/report.txt", base64.StdEncoding.EncodeToString([]byte("report"))); err != nil {
		t.Fatal(err)
	}
	got, err := Read(root, "nested/report.txt")
	if err != nil || string(mustDecode03110(t, got)) != "report" {
		t.Fatalf("read %q %v", got, err)
	}
	if err := Write(root, "nested/report.txt", base64.StdEncoding.EncodeToString([]byte("updated"))); err != nil {
		t.Fatal(err)
	}
	got, err = Read(root, "nested/report.txt")
	if err != nil || string(mustDecode03110(t, got)) != "updated" {
		t.Fatalf("атомарная замена %q: %v", got, err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "nested", "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(root, "nested/link"); err == nil {
		t.Fatal("обход ограничения чтения через символьную ссылку")
	}
	if err := Write(root, "nested/link", base64.StdEncoding.EncodeToString([]byte("replacement"))); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(outside)
	if string(b) != "unchanged" {
		t.Fatal("символьная ссылка изменила данные за пределами разрешённого inode")
	}
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(root, "linked-dir")); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(root, "linked-dir/outside"); err == nil {
		t.Fatal("обход ограничения через родительскую символьную ссылку")
	}
	if err := Write(root, "linked-dir/outside", base64.StdEncoding.EncodeToString([]byte("oops"))); err == nil {
		t.Fatal("запись через родительскую символьную ссылку")
	}
	if err := os.Link(outside, filepath.Join(root, "nested", "hardlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(root, "nested/hardlink"); err == nil {
		t.Fatal("чтение через жёсткую ссылку за пределами выданных прав")
	}
	if err := Write(root, "nested/hardlink", base64.StdEncoding.EncodeToString([]byte("safe"))); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(outside)
	if string(b) != "unchanged" {
		t.Fatal("жёсткая ссылка изменила данные за пределами разрешённого inode")
	}
	for _, rel := range []string{"../outside", "nested/../outside", "/etc/passwd", "nested//file", "nested/./file", "nested\\evil", "", "nested/"} {
		if _, err := Read(root, rel); err == nil {
			t.Fatalf("Небезопасное чтение %q", rel)
		}
		if err := Write(root, rel, base64.StdEncoding.EncodeToString([]byte("bad"))); err == nil {
			t.Fatalf("Небезопасная запись %q", rel)
		}
	}
	if err := Write(root, "oversized", base64.StdEncoding.EncodeToString(make([]byte, MaxFileBytes+1))); err == nil {
		t.Fatal("принят запрос с превышением допустимого размера")
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "large"), make([]byte, MaxFileBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(root, "nested/large"); err == nil {
		t.Fatal("допущено чтение сверх лимита")
	}
}
func mustDecode03110(t *testing.T, s string) []byte {
	t.Helper()
	b, e := base64.StdEncoding.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestScopedRootPolicy03110(t *testing.T) {
	root := t.TempDir()
	good := "{\"reports\":\"" + root + "\"}"
	roots, e := ParseRoots(good)
	if e != nil || roots["reports"] != root {
		t.Fatalf("корректный корневой каталог: %v", e)
	}
	bad := []string{"{bad}", "{\"../bad\":\"" + root + "\"}", "{\"reports\":\"/\"}", "{\"reports\":\"/not-a-real-directory\"}", "{} trailing"}
	for _, v := range bad {
		if _, e := ParseRoots(v); e == nil {
			t.Errorf("принят недопустимый корневой каталог %q", v)
		}
	}
	link := filepath.Join(t.TempDir(), "link")
	if e := os.Symlink(root, link); e != nil {
		t.Fatal(e)
	}
	if _, e := ParseRoots("{\"r\":\"" + link + "\"}"); e == nil {
		t.Fatal("Корневой каталог через символьную ссылку ошибочно принят")
	}
}
func TestSignedOutboundOrigin03110(t *testing.T) {
	grants := []string{"api.example.com:443", "service.example.org:8443"}
	for _, url := range []string{"https://api.example.com/v1", "https://api.example.com:443/v2", "https://service.example.org:8443/api"} {
		if !AllowedDestination(url, grants) {
			t.Fatalf("разрешённый источник отклонён %q", url)
		}
	}
	for _, url := range []string{"http://api.example.com", "https://other.example.com", "https://sub.api.example.com", "https://api.example.com.evil.net", "https://api.example.com:444", "https://user:pass@api.example.com", "https://127.0.0.1", "https://api.example.com./", "https://API.EXAMPLE.COM", "https://api.example.com:0443", "https://api.example.com/#fragment", "https://api.example.com%2f.evil/"} {
		if AllowedDestination(url, grants) {
			t.Fatalf("принят неутверждённый источник %q", url)
		}
	}
	if HasGrant(grants, "api.example.com:444") {
		t.Fatal("запрос к конечной точке без выданного разрешения")
	}
	if !strings.Contains(ErrDenied.Error(), "denied") {
		t.Fatal("неожиданный отказ")
	}
}
