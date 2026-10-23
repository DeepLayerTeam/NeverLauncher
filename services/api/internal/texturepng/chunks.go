package texturepng

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

func validateChunks(png []byte) error {
	offset := 8
	hasIHDR, hasIDAT, hasIEND := false, false, false
	for offset < len(png) {
		if len(png)-offset < 12 {
			return ErrInvalid
		}
		size := uint64(binary.BigEndian.Uint32(png[offset:]))
		// Integer-safe before slicing, including hostile 0xffffffff lengths.
		if size > uint64(len(png)-offset-12) {
			return ErrInvalid
		}
		begin := offset + 4
		chunkType := png[begin : begin+4]
		dataEnd := begin + 4 + int(size)
		content := png[begin:dataEnd]
		actualCRC := binary.BigEndian.Uint32(png[dataEnd:])
		if crc32.ChecksumIEEE(content) != actualCRC {
			return fmt.Errorf("%w: CRC mismatch", ErrInvalid)
		}
		for _, c := range chunkType {
			if !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') {
				return ErrInvalid
			}
		}
		switch string(chunkType) {
		case "IHDR":
			if hasIHDR || hasIDAT || offset != 8 || size != 13 {
				return ErrInvalid
			}
			hasIHDR = true
		case "IDAT":
			if !hasIHDR || hasIEND {
				return ErrInvalid
			}
			hasIDAT = true
		case "IEND":
			if !hasIHDR || !hasIDAT || hasIEND || size != 0 || dataEnd+4 != len(png) {
				return ErrInvalid
			}
			hasIEND = true
		case "acTL", "fcTL", "fdAT":
			return fmt.Errorf("%w: animated PNG is not a Minecraft texture", ErrInvalid)
		default:
			// Reject unknown critical chunks (ancillary chunks are stripped).
			if chunkType[0] >= 'A' && chunkType[0] <= 'Z' && !bytes.Equal(chunkType, []byte("PLTE")) {
				return fmt.Errorf("%w: unsupported critical chunk", ErrInvalid)
			}
		}
		offset = dataEnd + 4
		if hasIEND {
			break
		}
	}
	if !hasIHDR || !hasIDAT || !hasIEND {
		return ErrInvalid
	}
	return nil
}
