package storage

import (
	"bytes"
	"context"
	"errors"
	"io"

	"gitflic.ru/skif4er/launcher/services/api/internal/texturepng"
)

// VerifyTextureGA0260 проверяет не только сохранённые байты/SHA-256, но и то, что
// неизменяемая текстура полностью декодируема и канонична для скина/плаща Minecraft.
// Исторические не-изображения с правильно названным SHA не должны проходить GA-
// проверку целостности. Исходный VerifyTexture02511 проверяет только байты для инструментов,
// диагностирующих старые данные до решения об изоляции или миграции.
func VerifyTextureGA0260(ctx context.Context, store Storage, obj TextureBackupObject0253) TextureVerification02511 {
	result := VerifyTexture02511(ctx, store, obj)
	if result.Result != "ok" {
		return result
	}
	if err := ctx.Err(); err != nil {
		return TextureVerification02511{Digest: obj.Digest, Result: "cancelled", Detail: err.Error()}
	}
	reader, size, err := OpenTexture0252(store, obj.Digest)
	if err != nil {
		return TextureVerification02511{Digest: obj.Digest, Result: "unavailable", Detail: err.Error()}
	}
	content, readErr := io.ReadAll(io.LimitReader(&contextTextureReader02511{ctx: ctx, reader: reader}, texturepng.MaxEncodedBytes+1))
	closeErr := reader.Close()
	if readErr != nil {
		err = readErr
	} else if closeErr != nil {
		err = closeErr
	}
	if err != nil {
		return TextureVerification02511{Digest: obj.Digest, Result: "unavailable", Detail: err.Error()}
	}
	if len(content) > texturepng.MaxEncodedBytes || (size >= 0 && int64(len(content)) != size) {
		return TextureVerification02511{Digest: obj.Digest, Result: "corrupt", Detail: "Текстура превышает ограничение PNG или заявленный размер"}
	}
	// Сам PNG не кодирует выбор classic/slim. Оба варианта имеют
	// одинаковую допустимую геометрию скина 64x64. Ресурс 64x32 может быть старым скином
	// или плащом; подтверждённое соответствие должно возвращать ТОТ ЖЕ дайджест.
	for _, kind := range []string{"skin", "cape"} {
		processed, parseErr := texturepng.Process(bytes.NewReader(content), kind, "classic")
		if parseErr == nil && processed.Digest == obj.Digest && bytes.Equal(processed.PNG, content) {
			return result
		}
	}
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return TextureVerification02511{Digest: obj.Digest, Result: "cancelled", Detail: ctx.Err().Error()}
	}
	return TextureVerification02511{Digest: obj.Digest, Result: "corrupt", Detail: "Некорректный PNG скина или плаща Minecraft"}
}
