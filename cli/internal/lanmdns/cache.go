package lanmdns

// Ответы DNS-SD могут распределять PTR, SRV, TXT и A по нескольким UDP-пакетам. Этот
// ограниченный кэш на каждое обнаружение объединяет их по имени владельца и учитывает
// прощальные записи TTL=0, не считая полученную запись доверенной.

import (
	"encoding/binary"
	"net"
	"sort"
	"strings"
	"time"
)

type cachedPTR0498 struct{ expiry time.Time }
type cachedSRV0498 struct {
	target string
	port   int
	expiry time.Time
}
type cachedTXT0498 struct {
	fields map[string]string
	expiry time.Time
}
type discoveryCache0498 struct {
	ptr  map[string]cachedPTR0498
	srv  map[string]cachedSRV0498
	txt  map[string]cachedTXT0498
	addr map[string]map[string]time.Time
}

func newDiscoveryCache0498() *discoveryCache0498 {
	return &discoveryCache0498{ptr: map[string]cachedPTR0498{}, srv: map[string]cachedSRV0498{}, txt: map[string]cachedTXT0498{}, addr: map[string]map[string]time.Time{}}
}
func ttlDeadline0498(now time.Time, ttl uint32) time.Time {
	// Большие внешние TTL не могут продлевать жизнь кэша бесконечно.
	if ttl > 3600 {
		ttl = 3600
	}
	return now.Add(time.Duration(ttl) * time.Second)
}
func (c *discoveryCache0498) observe(packet []byte, now time.Time) {
	if len(packet) < 12 || binary.BigEndian.Uint16(packet[2:4])&0x800f != 0x8000 {
		return
	}
	_, records, err := parsePacket(packet)
	if err != nil {
		return
	}
	for _, rr := range records {
		if rr.class&0x7fff != 1 {
			continue
		}
		owner := strings.ToLower(rr.name)
		deadline := ttlDeadline0498(now, rr.ttl)
		switch rr.typ {
		case 12: // PTR only under the requested DNS-SD service.
			if owner != strings.ToLower(Service) {
				continue
			}
			pos := rr.offset
			name, err := getName(packet, &pos)
			if err != nil || pos != rr.offset+len(rr.data) || !strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(Service)) {
				continue
			}
			name = strings.ToLower(name)
			if rr.ttl == 0 {
				delete(c.ptr, name)
			} else if len(c.ptr) < 256 || c.ptr[name].expiry.After(now) {
				c.ptr[name] = cachedPTR0498{deadline}
			}
		case 33: // SRV target name can be compressed against this packet.
			if len(rr.data) < 7 {
				continue
			}
			port := int(binary.BigEndian.Uint16(rr.data[4:6]))
			pos := rr.offset + 6
			target, err := getName(packet, &pos)
			if err != nil || pos != rr.offset+len(rr.data) || port < 1 || port > 65535 {
				continue
			}
			if rr.ttl == 0 {
				delete(c.srv, owner)
			} else if len(c.srv) < 256 || c.srv[owner].expiry.After(now) {
				c.srv[owner] = cachedSRV0498{strings.ToLower(target), port, deadline}
			}
		case 16:
			fields, err := decodeTXT(rr.data)
			if err != nil {
				continue
			}
			if rr.ttl == 0 {
				delete(c.txt, owner)
			} else if len(c.txt) < 256 || c.txt[owner].expiry.After(now) {
				c.txt[owner] = cachedTXT0498{fields, deadline}
			}
		case 1:
			if len(rr.data) != 4 {
				continue
			}
			ip := net.IP(rr.data).String()
			if rr.ttl == 0 {
				delete(c.addr[owner], ip)
				continue
			}
			if _, ok := c.addr[owner]; !ok {
				if len(c.addr) >= 256 {
					continue
				}
				c.addr[owner] = map[string]time.Time{}
			}
			if len(c.addr[owner]) < 16 || !c.addr[owner][ip].IsZero() {
				c.addr[owner][ip] = deadline
			}
		}
	}
}
func (c *discoveryCache0498) endpoints(now time.Time) []Endpoint {
	out := make([]Endpoint, 0)
	for instance, ptr := range c.ptr {
		if !ptr.expiry.After(now) {
			continue
		}
		srv, ok := c.srv[instance]
		if !ok || !srv.expiry.After(now) {
			continue
		}
		txt, ok := c.txt[instance]
		if !ok || !txt.expiry.After(now) || txt.fields["txtvers"] != "1" || txt.fields["tls"] != "1" {
			continue
		}
		fp := txt.fields["fp"]
		if !FingerprintOK(fp) {
			continue
		}
		name := strings.TrimSuffix(instance, "."+strings.ToLower(Service))
		for ip, expires := range c.addr[srv.target] {
			parsed := net.ParseIP(ip)
			if !expires.After(now) || parsed == nil || parsed.To4() == nil || parsed.IsUnspecified() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsMulticast() || parsed.Equal(net.IPv4bcast) {
				continue
			}
			out = append(out, Endpoint{Instance: name, Host: srv.target, Address: ip, Port: srv.port, Fingerprint: strings.ToLower(fp)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Instance+out[i].Address < out[j].Instance+out[j].Address })
	return out
}
