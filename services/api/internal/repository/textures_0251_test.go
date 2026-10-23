package repository

import "testing"

func TestCanonicalTextureUUID0251(t *testing.T) {
	want := "acbd1234-5678-4bce-ae00-112233445566"
	for _, in := range []string{want, "ACBD123456784BCEAE00112233445566", "  ACBD1234-5678-4BCE-AE00-112233445566  "} {
		got, err := canonicalUUID0251(in)
		if err != nil || got != want {
			t.Fatalf("%q => %q %v", in, got, err)
		}
	}
	for _, in := range []string{"", "../skin.png", "acbd123456784bceae0011223344556z", "00000000-0000-0000-0000-00000000000", "https://example.org/x"} {
		if _, err := canonicalUUID0251(in); err == nil {
			t.Fatalf("accepted UUID %q", in)
		}
	}
}

func TestValidateTextureSelection0251(t *testing.T) {
	valid := [][3]string{{"skin", "classic", "public"}, {"skin", "slim", "unlisted"}, {"cape", "classic", "private"}}
	invalid := [][3]string{{"cape", "slim", "public"}, {"cape", "classic", "secret"}, {"skin", "wide", "public"}, {"unknown", "classic", "public"}}
	for _, v := range valid {
		if err := validateTextureSelection0251(v[0], v[1], v[2]); err != nil {
			t.Fatal(v, err)
		}
	}
	for _, v := range invalid {
		if err := validateTextureSelection0251(v[0], v[1], v[2]); err == nil {
			t.Fatal("accepted invalid", v)
		}
	}
}
