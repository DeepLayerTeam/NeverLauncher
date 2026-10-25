// Package lanmdns implements DNS-SD discovery for NeverLauncher backends without
// introducing a network trust anchor. All results are untrusted until TLS-pinned.
package lanmdns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

const Service = "_neverlauncher._tcp.local."
const multicast = "224.0.0.251:5353"
const maxMessage = 9000

type record struct {
	name   string
	typ    uint16
	class  uint16
	ttl    uint32
	data   []byte
	offset int
}
type question struct {
	name string
	typ  uint16
}

func putName(b *bytes.Buffer, name string) error {
	name = strings.TrimSuffix(name, ".")
	if len(name) > 253 || name == "" {
		return errors.New("invalid DNS name")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return errors.New("invalid DNS label")
		}
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.WriteByte(0)
	return nil
}
func getName(p []byte, pos *int) (string, error) {
	labels := make([]string, 0, 8)
	cur := *pos
	after := 0
	seen := map[int]bool{}
	for jumps := 0; jumps < 32; jumps++ {
		if cur >= len(p) {
			return "", errors.New("short DNS name")
		}
		if seen[cur] {
			return "", errors.New("cyclic DNS compression")
		}
		seen[cur] = true
		n := int(p[cur])
		if n&0xc0 == 0xc0 {
			if cur+1 >= len(p) {
				return "", errors.New("short compression pointer")
			}
			ptr := int(n&0x3f)<<8 | int(p[cur+1])
			if ptr >= cur {
				return "", errors.New("forward DNS compression pointer")
			}
			if after == 0 {
				after = cur + 2
			}
			cur = ptr
			continue
		}
		if n&0xc0 != 0 || n > 63 {
			return "", errors.New("invalid DNS label length")
		}
		cur++
		if n == 0 {
			if after != 0 {
				*pos = after
			} else {
				*pos = cur
			}
			if len(labels) == 0 {
				return ".", nil
			}
			return strings.Join(labels, ".") + ".", nil
		}
		if cur+n > len(p) {
			return "", errors.New("short DNS label")
		}
		labels = append(labels, string(p[cur:cur+n]))
		cur += n
		if len(strings.Join(labels, ".")) > 253 {
			return "", errors.New("DNS name too long")
		}
	}
	return "", errors.New("DNS compression recursion exceeded")
}
func appendRecord(b *bytes.Buffer, name string, typ uint16, ttl uint32, data []byte) error {
	if err := putName(b, name); err != nil {
		return err
	}
	_ = binary.Write(b, binary.BigEndian, typ)
	_ = binary.Write(b, binary.BigEndian, uint16(1))
	_ = binary.Write(b, binary.BigEndian, ttl)
	_ = binary.Write(b, binary.BigEndian, uint16(len(data)))
	_, _ = b.Write(data)
	return nil
}
func payloadName(name string) []byte { var b bytes.Buffer; _ = putName(&b, name); return b.Bytes() }
func buildQuery() []byte {
	var b bytes.Buffer
	b.Write(make([]byte, 12))
	p := b.Bytes()
	binary.BigEndian.PutUint16(p[4:6], 1)
	_ = putName(&b, Service)
	_ = binary.Write(&b, binary.BigEndian, uint16(12))
	_ = binary.Write(&b, binary.BigEndian, uint16(1))
	return b.Bytes()
}
func parsePacket(p []byte) ([]question, []record, error) {
	if len(p) < 12 || len(p) > maxMessage {
		return nil, nil, errors.New("invalid DNS packet length")
	}
	countq := int(binary.BigEndian.Uint16(p[4:6]))
	count := int(binary.BigEndian.Uint16(p[6:8])) + int(binary.BigEndian.Uint16(p[8:10])) + int(binary.BigEndian.Uint16(p[10:12]))
	if countq > 100 || count > 100 {
		return nil, nil, errors.New("DNS packet too many records")
	}
	at := 12
	qs := make([]question, 0, countq)
	rr := make([]record, 0, count)
	for i := 0; i < countq; i++ {
		name, err := getName(p, &at)
		if err != nil {
			return nil, nil, err
		}
		if at+4 > len(p) {
			return nil, nil, errors.New("short DNS question")
		}
		qs = append(qs, question{name, binary.BigEndian.Uint16(p[at : at+2])})
		at += 4
	}
	for i := 0; i < count; i++ {
		name, err := getName(p, &at)
		if err != nil {
			return nil, nil, err
		}
		if at+10 > len(p) {
			return nil, nil, errors.New("short DNS record")
		}
		typ := binary.BigEndian.Uint16(p[at : at+2])
		class := binary.BigEndian.Uint16(p[at+2 : at+4])
		ttl := binary.BigEndian.Uint32(p[at+4 : at+8])
		size := int(binary.BigEndian.Uint16(p[at+8 : at+10]))
		at += 10
		if at+size > len(p) {
			return nil, nil, errors.New("short DNS rdata")
		}
		rr = append(rr, record{name, typ, class, ttl, p[at : at+size], at})
		at += size
	}
	return qs, rr, nil
}
func encodeTXT(fields ...string) ([]byte, error) {
	var b bytes.Buffer
	for _, v := range fields {
		if len(v) > 255 {
			return nil, fmt.Errorf("DNS TXT too long")
		}
		b.WriteByte(byte(len(v)))
		b.WriteString(v)
	}
	return b.Bytes(), nil
}
func decodeTXT(data []byte) (map[string]string, error) {
	m := make(map[string]string)
	for len(data) > 0 {
		n := int(data[0])
		data = data[1:]
		if n > len(data) {
			return nil, errors.New("short TXT")
		}
		entry := string(data[:n])
		data = data[n:]
		k, v, ok := strings.Cut(entry, "=")
		if ok {
			m[strings.ToLower(k)] = v
		}
	}
	return m, nil
}
func ipForInterface() ([]net.IP, error) {
	list, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	seen := map[string]bool{}
	for _, iface := range list {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if !seen[ip.String()] {
				ips = append(ips, ip)
				seen[ip.String()] = true
			}
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("no usable IPv4 LAN interface")
	}
	return ips, nil
}
