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

	"gitflic.ru/skif4er/launcher/services/api/internal/texturepng"
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
		t.Fatalf("Отклонён корректный нормализованный PNG: %+v", checked)
	}
	// Имя объекта и совпадение SHA-256 сами по себе недостаточны как доказательство.
	plain := []byte("not an image, though stored under its correct SHA256")
	fake := textureFixture0253(plain)
	if _, _, err := PutTextureImmutable0253(ctx, store, fake.Digest, plain); err != nil {
		t.Fatal(err)
	}
	if checked := VerifyTexture02511(ctx, store, fake); checked.Result != "ok" {
		t.Fatalf("Неожиданное поведение устаревшей побайтовой проверки: %+v", checked)
	}
	if checked := VerifyTextureGA0260(ctx, store, fake); checked.Result != "corrupt" {
		t.Fatalf("Данные не в формате PNG приняты как текстура релизного качества: %+v", checked)
	}
	// Пиксели с корректным хешем, но неканоническим кодированием должны отклоняться:
	// сервис гарантирует нормализованные блобы и стабильный кэш с адресацией по содержимому.
	noncanonical := raw.Bytes()
	if !bytes.Equal(noncanonical, canonical.PNG) {
		digest := sha256.Sum256(noncanonical)
		noncanonicalDigest := hex.EncodeToString(digest[:])
		other := textureFixture0253(noncanonical)
		if _, _, err := PutTextureImmutable0253(ctx, store, noncanonicalDigest, noncanonical); err != nil {
			t.Fatal(err)
		}
		if checked := VerifyTextureGA0260(ctx, store, other); checked.Result != "corrupt" {
			t.Fatalf("Неканонический PNG прошёл проверку релиза: %+v", checked)
		}
	}
}
