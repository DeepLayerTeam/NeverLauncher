package storage

import (
	"bytes"
	"context"
	"errors"
	"io"

	"gitflic.ru/skif4er/launcher/services/api/internal/texturepng"
)

// VerifyTextureGA0260 checks not only stored bytes/SHA-256, but also that the
// immutable texture is a fully decodable and canonical Minecraft skin or cape.
// Historical non-image blobs with a correctly named SHA must not pass the GA
// integrity gate. The original VerifyTexture02511 remains byte-only for tools
// that diagnose old data before deciding whether to quarantine/migrate it.
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
		return TextureVerification02511{Digest: obj.Digest, Result: "corrupt", Detail: "texture exceeds PNG limit or declared byte size"}
	}
	// The PNG itself does not encode the classic/slim assignment. Both have
	// identical valid 64x64 skin geometry. A 64x32 asset may be a legacy skin
	// or a cape; an accepted match must still roundtrip to the SAME digest.
	for _, kind := range []string{"skin", "cape"} {
		processed, parseErr := texturepng.Process(bytes.NewReader(content), kind, "classic")
		if parseErr == nil && processed.Digest == obj.Digest && bytes.Equal(processed.PNG, content) {
			return result
		}
	}
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return TextureVerification02511{Digest: obj.Digest, Result: "cancelled", Detail: ctx.Err().Error()}
	}
	return TextureVerification02511{Digest: obj.Digest, Result: "corrupt", Detail: "not a valid canonical Minecraft skin/cape PNG"}
}
