// Пакет texturepng проверяет, полностью декодирует и детерминированно перекодирует
// загруженные PNG скинов/плащей Minecraft. Он НЕ доверяет одному имени файла, MIME или
// Недостаточно одной сигнатуры PNG. Лимиты проверяются до выделения памяти для декодированных пикселей.
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

// Process читает не более MaxEncodedBytes+1 байтов, проверяет полные
// данные PNG (включая CRC), ограничивает распаковку и повторно кодирует только матрицу
// пикселей, удаляя вспомогательные данные и неканонические представления пикселей.
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
	// Проверить полную последовательность блоков до передачи файла декодеру.
	// В частности, отклонять хвостовые данные, анимированные PNG и ошибочные CRC,
	// в том числе во вспомогательных блоках, которые image/png иначе может пропустить.
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
	// NRGBA унифицирует представление каналов для grayscale, palette, RGBA и т. п.
	// Для полностью прозрачных пикселей каналы RGB обнуляются, поэтому одинаковое
	// видимое содержимое нормализуется в одинаковый дайджест SHA-256.
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
	// Minecraft поддерживает целочисленные HD-масштабы исходного макета 64px;
	// устаревшая геометрия скина 64x32 появилась до рук Alex/slim.
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
