package texturepng

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"testing"
)

func texture(w, h int) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	img.SetNRGBA(0, 0, color.NRGBA{R: 200, G: 50, B: 90, A: 255})
	var b bytes.Buffer
	_ = png.Encode(&b, img)
	return b.Bytes()
}
func TestSkinAndCapeValidation(t *testing.T) {
	for _, tt := range []struct {
		kind, model string
		w, h        int
		valid       bool
	}{
		{"skin", "classic", 64, 64, true}, {"skin", "slim", 64, 64, true},
		{"skin", "classic", 64, 32, true}, {"skin", "slim", 64, 32, false},
		{"cape", "classic", 64, 32, true}, {"cape", "slim", 64, 32, false},
		{"cape", "classic", 128, 64, true}, {"skin", "classic", 65, 64, false},
		{"skin", "classic", 2048, 2048, false}, {"cape", "classic", 64, 64, false},
	} {
		_, err := Process(bytes.NewReader(texture(tt.w, tt.h)), tt.kind, tt.model)
		if (err == nil) != tt.valid {
			t.Errorf("%+v: %v", tt, err)
		}
	}
}
func TestRejectsCorruptionAndTrailingData(t *testing.T) {
	base := texture(64, 64)
	candidates := [][]byte{nil, []byte("not a png"), append(append([]byte{}, base...), 0x42), append([]byte{}, base[:len(base)-4]...), bytes.Repeat([]byte{42}, MaxEncodedBytes+1)}
	corrupt := append([]byte{}, base...)
	corrupt[len(corrupt)-9] ^= 1
	candidates = append(candidates, corrupt)
	for i, data := range candidates {
		if _, err := Process(bytes.NewReader(data), "skin", "classic"); err == nil {
			t.Errorf("invalid case %d accepted", i)
		}
	}
	_, err := Process(bytes.NewReader(candidates[4]), "skin", "classic")
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("size: %v", err)
	}
}
func TestDeterministicNormalization(t *testing.T) {
	original := texture(64, 64)
	a, e := Process(bytes.NewReader(original), "skin", "classic")
	if e != nil {
		t.Fatal(e)
	}
	b, e := Process(bytes.NewReader(a.PNG), "skin", "classic")
	if e != nil {
		t.Fatal(e)
	}
	if a.Digest != b.Digest || !bytes.Equal(a.PNG, b.PNG) {
		t.Fatal("not deterministic")
	}
	if a.Width != 64 || a.Height != 64 {
		t.Fatalf("bad dimensions %+v", a)
	}
}
func TestBoundedReader(t *testing.T) {
	r := io.LimitReader(bytes.NewReader(bytes.Repeat([]byte("x"), MaxEncodedBytes+100)), MaxEncodedBytes+100)
	_, err := Process(r, "skin", "classic")
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("expected too large: %v", err)
	}
}
