package prestarter

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"image/png"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// Branding0355 is deliberately data-only. Scripts, HTML, CSS and remote image
// locations are not part of the owner-signed bootstrap surface.
type BrandNews0355 struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

var color0355 = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
var pngMagic0355 = []byte{137, 80, 78, 71, 13, 10, 26, 10}

func brandHTTPS0355(raw string) bool {
	if len(raw) > 2048 || strings.TrimSpace(raw) != raw || strings.Contains(raw, "\\") || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == "" && u.Opaque == "" && strings.HasPrefix(raw, "https://")
}

func validatePng0355(raw string, max, maxWidth, maxHeight int) error {
	if raw == "" {
		return nil
	}
	if len(raw) > base64.StdEncoding.EncodedLen(max) {
		return errors.New("PNG exceeds signed bootstrap budget")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(raw)
	if err != nil || len(data) < 24 || len(data) > max || !bytes.Equal(data[:8], pngMagic0355) || !bytes.Equal(data[12:16], []byte("IHDR")) || binary.BigEndian.Uint32(data[8:12]) != 13 ||
		binary.BigEndian.Uint32(data[16:20]) == 0 || binary.BigEndian.Uint32(data[16:20]) > uint32(maxWidth) ||
		binary.BigEndian.Uint32(data[20:24]) == 0 || binary.BigEndian.Uint32(data[20:24]) > uint32(maxHeight) {
		return errors.New("branding resource must be an embedded PNG")
	}
	if _, err := png.Decode(bytes.NewReader(data)); err != nil {
		return fmt.Errorf("invalid or truncated PNG: %w", err)
	}
	return nil
}
func (b Branding) Validate0355() error {
	if len(b.DisplayName) < 1 || len(b.DisplayName) > 80 || len(b.Publisher) < 1 || len(b.Publisher) > 96 || strings.IndexFunc(b.DisplayName+b.Publisher, unicode.IsControl) >= 0 {
		return errors.New("invalid signed brand identity")
	}
	if b.WebsiteURL != "" && !brandHTTPS0355(b.WebsiteURL) {
		return errors.New("branding website must be HTTPS")
	}
	for _, v := range []string{b.AccentColor, b.BackgroundColor, b.TextColor} {
		if v != "" && !color0355.MatchString(v) {
			return errors.New("brand colors must be #RRGGBB")
		}
	}
	if b.Locale != "" && b.Locale != "ru" && b.Locale != "en" {
		return errors.New("unsupported brand locale")
	}
	for label, asset := range map[string]string{"logoPng": b.LogoPNG, "iconPng": b.IconPNG, "splashPng": b.SplashPNG} {
		width, height := 1024, 1024
		if label == "splashPng" {
			width, height = 2048, 1200
		}
		if err := validatePng0355(asset, 128*1024, width, height); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
	}
	if len(b.News) > 5 {
		return errors.New("maximum five signed news links")
	}
	for _, item := range b.News {
		if len(item.Title) == 0 || len(item.Title) > 120 || strings.IndexFunc(item.Title, unicode.IsControl) >= 0 || !brandHTTPS0355(item.URL) {
			return errors.New("invalid signed news link")
		}
	}
	return nil
}
