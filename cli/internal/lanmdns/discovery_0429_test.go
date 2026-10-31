package lanmdns

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func TestDiscoveryRejectsPacketsThatAreNotSuccessfulAnswers(t *testing.T) {
	b, err := announceMessage("SafeLAN", 19443, strings.Repeat("a", 64), []net.IP{net.ParseIP("192.168.1.22")}, 120)
	if err != nil {
		t.Fatal(err)
	}
	items, err := ParseAdvertisement(b)
	if err != nil || len(items) != 1 {
		t.Fatalf("valid DNS-SD response rejected: %v %v", items, err)
	}
	badQR := append([]byte(nil), b...)
	binary.BigEndian.PutUint16(badQR[2:4], 0)
	if _, err := ParseAdvertisement(badQR); err == nil {
		t.Fatal("DNS question carrying spoofed answers accepted")
	}
	badRCODE := append([]byte(nil), b...)
	binary.BigEndian.PutUint16(badRCODE[2:4], 0x8403)
	if _, err := ParseAdvertisement(badRCODE); err == nil {
		t.Fatal("DNS error response accepted")
	}
	// A bad record class must not provide a verified endpoint.
	badClass := append([]byte(nil), b...)
	_, rr, err := parsePacket(badClass)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rr {
		if r.typ == 1 {
			binary.BigEndian.PutUint16(badClass[r.offset-8:r.offset-6], 3)
		}
	}
	items, err = ParseAdvertisement(badClass)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatal("unsupported DNS record class accepted")
	}
}
