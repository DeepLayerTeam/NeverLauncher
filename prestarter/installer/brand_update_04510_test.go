package installer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	prestarter "github.com/DeepLayerTeam/Launcher/prestarter"
)

// The installer is exercised with the real disk lock, two-slot commit,
// executed Prestarter and signed payloads. Only the game binary is a fixture.
func TestBrandedSignedUpdateIsTransactional04510(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("script-based Prestarter fixture")
	}
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "xdg"))
	opts := signedBundle(t, root, false)
	raw, err := os.ReadFile(filepath.Join(opts.Bundle, "bootstrap.signed.json"))
	if err != nil {
		t.Fatal(err)
	}
	var original prestarter.Envelope
	if err := json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opts.TrustedKey = hex.EncodeToString(pub)
	cfg, _, err := prestarter.VerifyEnvelope(raw, opts.TrustedKey)
	if err == nil {
		t.Fatal("must not accept old fixture trust root")
	}
	// Obtain the fixture config without trusting the original signer; test
	// changes are re-signed by our new, pinned test key.
	var tmpCfg prestarter.Config
	if err := json.Unmarshal(mustBase64(t, original.Payload), &tmpCfg); err != nil {
		t.Fatal(err)
	}
	cfg = tmpCfg
	var iconBuf bytes.Buffer
	icon := image.NewNRGBA(image.Rect(0, 0, 2, 2))
	icon.Set(0, 0, color.NRGBA{R: 255, A: 255})
	if err := png.Encode(&iconBuf, icon); err != nil {
		t.Fatal(err)
	}
	cfg.Branding.IconPNG = base64.StdEncoding.EncodeToString(iconBuf.Bytes())
	sign := func(bundle string, c prestarter.Config, executable string) {
		t.Helper()
		if err := os.MkdirAll(bundle, 0700); err != nil {
			t.Fatal(err)
		}
		c.InstallerTargets[0].Prestarter = artifact([]byte(executable))
		data, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := prestarter.SignedEnvelope(data, priv)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bundle, "bootstrap.signed.json"), signed, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bundle, binaryName()), []byte(executable), 0700); err != nil {
			t.Fatal(err)
		}
	}
	script1 := "#!/bin/sh\nexit 0\n"
	sign(opts.Bundle, cfg, script1)
	if err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if err := VerifyInstalled(opts); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "linux" {
		desktop, err := os.ReadFile(filepath.Join(root, "xdg", "applications", "launcher.desktop"))
		if err != nil || !bytes.Contains(desktop, []byte("Icon=")) {
			t.Fatal("branded desktop shortcut missing signed icon")
		}
		// The signed image is present beside the verified installed bundle.
		base, err := filepath.Glob(filepath.Join(opts.Root, ".launcher-installer", "releases", "*", "brand-icon.png"))
		if err != nil || len(base) != 1 {
			t.Fatalf("missing branded installed icon: %v %v", base, err)
		}
		b, err := os.ReadFile(base[0])
		if err != nil || !bytes.Equal(b, iconBuf.Bytes()) {
			t.Fatal("installed icon not signed PNG bytes")
		}
	}
	i, err := newInstall(opts)
	if err != nil {
		t.Fatal(err)
	}
	before, err := i.current()
	if err != nil {
		t.Fatal(err)
	}
	next := filepath.Join(root, "next")
	opts.Bundle = next
	cfg.Branding.DisplayName = "New Brand"
	sign(next, cfg, script1)
	if err := Update(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	updated, err := i.current()
	if err != nil {
		t.Fatal(err)
	}
	if updated.Generation != before.Generation+1 || updated.Release == before.Release {
		t.Fatalf("signed update not committed: before=%+v after=%+v", before, updated)
	}
	bad := filepath.Join(root, "bad")
	opts.Bundle = bad
	cfg.Branding.DisplayName = "Broken Brand"
	sign(bad, cfg, "#!/bin/sh\nexit 32\n")
	if err := Update(context.Background(), opts); err == nil {
		t.Fatal("failed Prestarter update accepted")
	}
	afterFail, err := i.current()
	if err != nil {
		t.Fatal(err)
	}
	if afterFail.Generation != updated.Generation || afterFail.Release != updated.Release {
		t.Fatal("failed update moved trusted active slot")
	}
	hijack := filepath.Join(root, "other-project")
	opts.Bundle = hijack
	cfg.ProjectID = "other-project"
	sign(hijack, cfg, script1)
	if err := Update(context.Background(), opts); err == nil {
		t.Fatal("cross-project update accepted")
	}
	if err := VerifyInstalled(opts); err != nil {
		t.Fatal(err)
	}
}

func mustBase64(t *testing.T, s string) []byte {
	t.Helper()
	d, e := base64.StdEncoding.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return d
}
