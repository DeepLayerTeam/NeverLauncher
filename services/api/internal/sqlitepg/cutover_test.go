package sqlitepg

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestFileCatalogDigest0475IncludesEveryField(t *testing.T) {
	a := []fileObject0474{{"project", "version", "a.jar", strings.Repeat("a", 64), 10}}
	b := []fileObject0474{{"project", "version", "a.jar", strings.Repeat("b", 64), 10}}
	c := []fileObject0474{{"project", "version", "b.jar", strings.Repeat("a", 64), 10}}
	aa, e := json.Marshal(a)
	if e != nil {
		t.Fatal(e)
	}
	bb, e := json.Marshal(b)
	if e != nil {
		t.Fatal(e)
	}
	cc, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	if string(aa) == string(bb) || string(aa) == string(cc) || !strings.Contains(string(aa), "a.jar") {
		t.Fatalf("при сериализации каталога потеряны SHA или путь: %s", aa)
	}
}

func TestCutoverCheck0475FailsBeforeNetwork(t *testing.T) {
	if _, err := VerifyCutover0475(context.Background(), "", "bad", "p", "owner@example.invalid"); err == nil {
		t.Fatal("принята недействительная квитанция или пустая строка подключения DSN")
	}
}
