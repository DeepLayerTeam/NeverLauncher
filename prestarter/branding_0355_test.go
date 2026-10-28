package prestarter

import (
	"encoding/base64"
	"testing"
)

func TestSignedBranding0355RejectsActiveContent(t *testing.T) {
	good := Branding{DisplayName: "Example", Publisher: "Operator", AccentColor: "#24aabb", BackgroundColor: "#101822", TextColor: "#ffffff", Locale: "ru", News: []BrandNews0355{{Title: "Update", URL: "https://example.org/news"}}}
	if err := good.Validate0355(); err != nil {
		t.Fatal(err)
	}
	// Real PNG with valid IHDR, IDAT, IEND and CRC; truncated headers are rejected.
	png, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGPgEpH7DwABpAE8k4sOtwAAAABJRU5ErkJggg==")
	if err != nil {
		t.Fatal(err)
	}
	good.LogoPNG = base64.StdEncoding.EncodeToString(png)
	if err := good.Validate0355(); err != nil {
		t.Fatal(err)
	}
	cases := []Branding{good, good, good, good, good}
	cases[0].AccentColor = "red; background:url(https://evil.test)"
	cases[1].LogoPNG = base64.StdEncoding.EncodeToString([]byte("<svg><script/></svg>"))
	cases[2].News = []BrandNews0355{{Title: "X", URL: "javascript:alert(1)"}}
	cases[3].Locale = "../../etc"
	cases[4].WebsiteURL = "https://evil.test/#fragment"
	for i, b := range cases {
		if b.Validate0355() == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
}
