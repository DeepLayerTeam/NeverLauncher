package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"image"
	"image/color"
	"image/png"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/texturepng"
)

func TestTextureGA0260VerificationRequiresCanonicalPNG(t *testing.T) {
	ctx := context.Background()
	store := NewLocalStorage(t.TempDir())
	img := image.NewNRGBA(image.Rect(0, 0, 64, 64))
	img.Set(2, 2, color.NRGBA{R: 80, G: 90, B: 100, A: 255})
	var raw bytes.Buffer
	if err := png.Encode(&raw, img); err != nil {
		t.Fatal(err)
	}
	canonical, err := texturepng.Process(bytes.NewReader(raw.Bytes()), "skin", "slim")
	if err != nil {
		t.Fatal(err)
	}
	obj := textureFixture0253(canonical.PNG)
	if _, _, err := PutTextureImmutable0253(ctx, store, obj.Digest, canonical.PNG); err != nil {
		t.Fatal(err)
	}
	if checked := VerifyTextureGA0260(ctx, store, obj); checked.Result != "ok" {
		t.Fatalf("valid normalized PNG rejected: %+v", checked)
	}
	// Object naming and SHA-256 matching alone are not sufficient evidence.
	plain := []byte("not an image, though stored under its correct SHA256")
	fake := textureFixture0253(plain)
	if _, _, err := PutTextureImmutable0253(ctx, store, fake.Digest, plain); err != nil {
		t.Fatal(err)
	}
	if checked := VerifyTexture02511(ctx, store, fake); checked.Result != "ok" {
		t.Fatalf("unexpected legacy byte-verification behavior: %+v", checked)
	}
	if checked := VerifyTextureGA0260(ctx, store, fake); checked.Result != "corrupt" {
		t.Fatalf("non-PNG bytes accepted as release-quality texture: %+v", checked)
	}
	// Hash-valid but not canonically encoded pixels must be rejected: the
	// service promises normalized blobs and a stable content-addressed cache.
	noncanonical := raw.Bytes()
	if !bytes.Equal(noncanonical, canonical.PNG) {
		digest := sha256.Sum256(noncanonical)
		noncanonicalDigest := hex.EncodeToString(digest[:])
		other := textureFixture0253(noncanonical)
		if _, _, err := PutTextureImmutable0253(ctx, store, noncanonicalDigest, noncanonical); err != nil {
			t.Fatal(err)
		}
		if checked := VerifyTextureGA0260(ctx, store, other); checked.Result != "corrupt" {
			t.Fatalf("noncanonical PNG passed release check: %+v", checked)
		}
	}
}
