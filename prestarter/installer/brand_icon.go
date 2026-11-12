package installer

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"path/filepath"
	"runtime"

	prestarter "github.com/DeepLayerTeam/Launcher/prestarter"
)

// materializeBrandIcon записывает только декодированные изображения из проверенной конфигурации начальной загрузки,
// подписанного владельцем. Windows Explorer ожидает ICO, Linux принимает PNG.
func materializeBrandIcon(dir string, brand *prestarter.Branding) (string, error) {
	if brand == nil || brand.IconPNG == "" {
		return "", nil
	}
	data, err := base64.StdEncoding.Strict().DecodeString(brand.IconPNG)
	if err != nil {
		return "", err
	}
	source, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	if runtime.GOOS != "windows" {
		path := filepath.Join(dir, "brand-icon.png")
		return path, atomicWrite(path, data)
	}
	bounds := source.Bounds()
	w, h := bounds.Dx(), bounds.Dy()
	if w > 256 || h > 256 {
		if w > h {
			h = h * 256 / w
			w = 256
		} else {
			w = w * 256 / h
			h = 256
		}
	}
	if w < 1 || h < 1 {
		return "", fmt.Errorf("Недопустимые размеры значка")
	}
	resized := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			orig := source.At(bounds.Min.X+x*bounds.Dx()/w, bounds.Min.Y+y*bounds.Dy()/h)
			resized.Set(x, y, color.NRGBAModel.Convert(orig))
		}
	}
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, resized); err != nil {
		return "", err
	}
	pngBytes := encoded.Bytes()
	var ico bytes.Buffer
	// Одно 32-битное изображение на основе PNG; Windows Vista и новее.
	if err := binary.Write(&ico, binary.LittleEndian, []uint16{0, 1, 1}); err != nil {
		return "", err
	}
	ico.WriteByte(byte(w % 256))
	ico.WriteByte(byte(h % 256))
	ico.Write([]byte{0, 0})
	if err := binary.Write(&ico, binary.LittleEndian, []uint16{1, 32}); err != nil {
		return "", err
	}
	if err := binary.Write(&ico, binary.LittleEndian, uint32(len(pngBytes))); err != nil {
		return "", err
	}
	if err := binary.Write(&ico, binary.LittleEndian, uint32(22)); err != nil {
		return "", err
	}
	ico.Write(pngBytes)
	path := filepath.Join(dir, "brand-icon.ico")
	return path, atomicWrite(path, ico.Bytes())
}
