package webauthn

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type cborDecoder struct {
	b []byte
	i int
}

func decodeCBOR(b []byte) (any, int, error) {
	d := &cborDecoder{b: b}
	v, err := d.read()
	return v, d.i, err
}

func (d *cborDecoder) read() (any, error) {
	if d.i >= len(d.b) {
		return nil, errors.New("CBOR: unexpected EOF")
	}
	h := d.b[d.i]
	d.i++
	major, ai := h>>5, h&0x1f
	n, err := d.argument(ai)
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		return n, nil
	case 1:
		if n > uint64(^uint64(0)>>1) {
			return nil, errors.New("CBOR: negative integer overflow")
		}
		return -1 - int64(n), nil
	case 2:
		if n > uint64(len(d.b)-d.i) {
			return nil, errors.New("CBOR: byte string overflow")
		}
		out := append([]byte(nil), d.b[d.i:d.i+int(n)]...)
		d.i += int(n)
		return out, nil
	case 3:
		if n > uint64(len(d.b)-d.i) {
			return nil, errors.New("CBOR: text overflow")
		}
		out := string(d.b[d.i : d.i+int(n)])
		d.i += int(n)
		return out, nil
	case 4:
		if n > 1024 {
			return nil, errors.New("CBOR: array too large")
		}
		out := make([]any, 0, int(n))
		for j := uint64(0); j < n; j++ {
			v, e := d.read()
			if e != nil {
				return nil, e
			}
			out = append(out, v)
		}
		return out, nil
	case 5:
		if n > 1024 {
			return nil, errors.New("CBOR: map too large")
		}
		out := make(map[any]any, int(n))
		for j := uint64(0); j < n; j++ {
			k, e := d.read()
			if e != nil {
				return nil, e
			}
			v, e := d.read()
			if e != nil {
				return nil, e
			}
			switch k.(type) {
			case string, int64, uint64:
			default:
				return nil, errors.New("CBOR: unsupported map key")
			}
			out[k] = v
		}
		return out, nil
	case 6:
		return d.read() // semantic tags are irrelevant for WebAuthn structures handled here.
	case 7:
		switch ai {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22, 23:
			return nil, nil
		default:
			return nil, fmt.Errorf("CBOR: unsupported simple value %d", ai)
		}
	default:
		return nil, errors.New("CBOR: unsupported major type")
	}
}

func (d *cborDecoder) argument(ai byte) (uint64, error) {
	switch {
	case ai < 24:
		return uint64(ai), nil
	case ai == 24:
		if d.i+1 > len(d.b) {
			return 0, errors.New("CBOR: EOF")
		}
		v := uint64(d.b[d.i])
		d.i++
		return v, nil
	case ai == 25:
		if d.i+2 > len(d.b) {
			return 0, errors.New("CBOR: EOF")
		}
		v := uint64(binary.BigEndian.Uint16(d.b[d.i:]))
		d.i += 2
		return v, nil
	case ai == 26:
		if d.i+4 > len(d.b) {
			return 0, errors.New("CBOR: EOF")
		}
		v := uint64(binary.BigEndian.Uint32(d.b[d.i:]))
		d.i += 4
		return v, nil
	case ai == 27:
		if d.i+8 > len(d.b) {
			return 0, errors.New("CBOR: EOF")
		}
		v := binary.BigEndian.Uint64(d.b[d.i:])
		d.i += 8
		return v, nil
	default:
		return 0, errors.New("CBOR: indefinite/reserved length is not accepted")
	}
}

func mapGet(m map[any]any, key any) (any, bool) { v, ok := m[key]; return v, ok }
func intValue(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case uint64:
		if x <= uint64(^uint64(0)>>1) {
			return int64(x), true
		}
	}
	return 0, false
}
