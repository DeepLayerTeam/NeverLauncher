// Package texturepng validates, fully decodes and deterministically rewrites
// uploaded Minecraft skin/cape PNGs. It trusts the filename, MIME type or
// PNG signature alone. Limits are checked before allocating decoded pixels.
package texturepng

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"io"
)

const (
	MaxEncodedBytes = 4 << 20     // bounded compressed bytes read per upload
	MaxPixels       = 1024 * 1024 // at most 4MiB decoded RGBA image
	MaxDimension    = 1024
)

var ErrInvalid = errors.New("invalid Minecraft texture PNG")
var ErrTooLarge = errors.New("texture size limit exceeded")

type Result struct {
	PNG    []byte
	Digest string
	Width  int
	Height int
	Kind   string
	Model  string
}

// Process reads no more than MaxEncodedBytes+1 bytes, validates the complete
// PNG data (including CRCs), bounds decompression and re-encodes only the pixel
// matrix, stripping any ancillary data and non-canonical pixel representations.
func Process(src io.Reader, kind, model string) (Result, error) {
	var result Result
	if kind != "skin" && kind != "cape" {
		return result, fmt.Errorf("%w: invalid kind", ErrInvalid)
	}
	if model != "classic" && model != "slim" {
		return result, fmt.Errorf("%w: invalid model", ErrInvalid)
	}
	if kind == "cape" && model != "classic" {
		return result, fmt.Errorf("%w: capes have no slim model", ErrInvalid)
	}
	content, err := io.ReadAll(io.LimitReader(src, MaxEncodedBytes+1))
	if err != nil {
		return result, fmt.Errorf("read PNG: %w", err)
	}
	if len(content) > MaxEncodedBytes {
		return result, ErrTooLarge
	}
	if len(content) < 33 || !bytes.Equal(content[:8], []byte("\x89PNG\r\n\x1a\n")) {
		return result, ErrInvalid
	}
	// Check complete chunk sequence before handing the file to the decoder.
	// In particular reject trailing payloads, animated PNGs and malformed CRCs
	// including those on ancillary chunks that image/png may otherwise skip.
	if err := validateChunks(content); err != nil {
		return result, err
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(content))
	if err != nil {
		return result, fmt.Errorf("%w: PNG header: %v", ErrInvalid, err)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > MaxDimension || cfg.Height > MaxDimension || int64(cfg.Width)*int64(cfg.Height) > MaxPixels {
		return result, ErrTooLarge
	}
	if !validGeometry(kind, model, cfg.Width, cfg.Height) {
		return result, fmt.Errorf("%w: unsupported Minecraft texture geometry", ErrInvalid)
	}
	decoded, err := png.Decode(bytes.NewReader(content))
	if err != nil {
		return result, fmt.Errorf("%w: PNG decoding failed: %v", ErrInvalid, err)
	}
	if decoded.Bounds().Dx() != cfg.Width || decoded.Bounds().Dy() != cfg.Height {
		return result, ErrInvalid
	}
	// NRGBA fixes channel representation across grayscale, palette, RGBA etc.
	// Fully transparent pixels have their RGB channels zeroed, so identical
	// visible content normalizes to an identical SHA-256 digest.
	normalized := image.NewNRGBA(image.Rect(0, 0, cfg.Width, cfg.Height))
	draw.Draw(normalized, normalized.Bounds(), decoded, decoded.Bounds().Min, draw.Src)
	for i := 0; i < len(normalized.Pix); i += 4 {
		if normalized.Pix[i+3] == 0 {
			normalized.Pix[i], normalized.Pix[i+1], normalized.Pix[i+2] = 0, 0, 0
		}
	}
	var output bytes.Buffer
	if err := (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(&output, normalized); err != nil {
		return result, err
	}
	if output.Len() > MaxEncodedBytes {
		return result, ErrTooLarge
	}
	sum := sha256.Sum256(output.Bytes())
	return Result{PNG: output.Bytes(), Digest: hex.EncodeToString(sum[:]), Width: cfg.Width, Height: cfg.Height, Kind: kind, Model: model}, nil
}

func validGeometry(kind, model string, width, height int) bool {
	// Minecraft supports integer HD scales of the original 64px layout;
	// legacy 64x32 skin geometry predates Alex/slim arms.
	if width < 64 || width%64 != 0 || width > MaxDimension {
		return false
	}
	scale := width / 64
	if kind == "cape" {
		return height == 32*scale
	}
	if height == 64*scale {
		return true
	}
	return model == "classic" && height == 32*scale
}
