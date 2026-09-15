package storage

import (
	"context"
	"io"
	"strings"
	"testing"
)

func TestLocalStorageSaveOpenHealth(t *testing.T) {
	store := NewLocalStorage(t.TempDir())
	key, size, err := store.Save("project", "version", "mods/example.jar", strings.NewReader("content"))
	if err != nil {
		t.Fatalf("Save вернул ошибку: %v", err)
	}
	if key != "project/version/mods/example.jar" || size != 7 {
		t.Fatalf("неожиданный key/size: %q %d", key, size)
	}
	reader, openedSize, err := store.Open("project", "version", "mods/example.jar")
	if err != nil {
		t.Fatalf("Open вернул ошибку: %v", err)
	}
	defer reader.Close()
	data, _ := io.ReadAll(reader)
	if string(data) != "content" || openedSize != 7 {
		t.Fatalf("неожиданные данные: %q %d", string(data), openedSize)
	}
	if err := store.Health(context.Background()); err != nil {
		t.Fatalf("Health вернул ошибку: %v", err)
	}
}

func TestLocalStorageRejectsPathTraversal(t *testing.T) {
	store := NewLocalStorage(t.TempDir())
	cases := []string{"../evil.jar", "mods/../../evil.jar", "/absolute.jar"}
	for _, item := range cases {
		if _, _, err := store.Save("project", "version", item, strings.NewReader("x")); err == nil {
			t.Fatalf("Save принял небезопасный путь %q", item)
		}
	}
	if _, _, err := store.Save("../project", "version", "file.jar", strings.NewReader("x")); err == nil {
		t.Fatal("Save принял небезопасный projectId")
	}
}
