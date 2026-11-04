package lanmdns

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// Each DNS response contains exactly one RR, as Bonjour/Avahi may deliver.
func TestMDNSSplitRepliesAndTTL0498(t *testing.T) {
	now := time.Unix(1700000000, 0)
	c := newDiscoveryCache0498()
	fp := strings.Repeat("ab", 32)
	ip := net.ParseIP("192.168.4.6").To4()
	inst := "world." + Service
	host := "world.local."
	build := func(name string, typ uint16, ttl uint32, payload []byte) []byte {
		header := make([]byte, 12)
		binary.BigEndian.PutUint16(header[2:4], 0x8400)
		binary.BigEndian.PutUint16(header[6:8], 1)
		var buffer bytes.Buffer
		buffer.Write(header)
		if err := appendRecord(&buffer, name, typ, ttl, payload); err != nil {
			t.Fatal(err)
		}
		return buffer.Bytes()
	}
	ptr := build(Service, 12, 120, payloadName(inst))
	var srvData []byte
	srvData = append(srvData, 0, 0, 0, 0, 0x24, 0xe3)
	srvData = append(srvData, payloadName(host)...)
	srv := build(inst, 33, 120, srvData)
	txtData, err := encodeTXT("txtvers=1", "tls=1", "fp="+fp)
	if err != nil {
		t.Fatal(err)
	}
	txt := build(inst, 16, 120, txtData)
	address := build(host, 1, 120, ip)
	for _, part := range [][]byte{ptr, srv, txt} {
		c.observe(part, now)
	}
	if got := c.endpoints(now); len(got) != 0 {
		t.Fatalf("partial DNS response advertised %#v", got)
	}
	c.observe(address, now)
	if got := c.endpoints(now); len(got) != 1 || got[0].Address != "192.168.4.6" || got[0].Port != 9443 || got[0].Verified {
		t.Fatalf("split DNS joining failed %#v", got)
	}
	c.observe(build(Service, 12, 0, payloadName(inst)), now.Add(time.Second))
	if got := c.endpoints(now.Add(time.Second)); len(got) != 0 {
		t.Fatalf("withdrawn entry retained: %#v", got)
	}
	c.observe(ptr, now.Add(2*time.Second))
	if got := c.endpoints(now.Add(121 * time.Second)); len(got) != 0 {
		t.Fatalf("expired entry retained: %#v", got)
	}
}
