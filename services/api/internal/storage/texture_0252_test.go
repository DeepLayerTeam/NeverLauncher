package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sync"
	"testing"
)

func TestTextureImmutableConcurrent0252(t *testing.T) {
	s := NewLocalStorage(t.TempDir())
	data := []byte("normalized PNG payload used by storage layer")
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	const n = 12
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := SaveTexture0252(s, digest, data)
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	r, size, err := OpenTexture0252(s, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len(data)) || !bytes.Equal(got, data) {
		t.Fatal("object corrupted")
	}
	if _, _, err := SaveTexture0252(s, digest, []byte("different")); err == nil {
		t.Fatal("accepted wrong digest")
	}
	if _, _, err := OpenTexture0252(s, "../../etc/passwd"); err == nil {
		t.Fatal("path traversal")
	}
}
