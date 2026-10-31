package lanmdns

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Endpoint struct {
	Instance    string `json:"instance"`
	Host        string `json:"host"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	Fingerprint string `json:"fingerprint"`
	Verified    bool   `json:"verified"`
}

func FingerprintOK(fp string) bool {
	if len(fp) != 64 {
		return false
	}
	_, err := hex.DecodeString(fp)
	return err == nil
}
func ValidateURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" || u.Hostname() == "" || u.Port() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return nil, errors.New("LAN endpoint must be an https URL with hostname and explicit port")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid LAN TLS port")
	}
	return u, nil
}

// ValidatePublishAddress rejects remote, loopback-only, and spoofed advertise
// targets. LAN discovery advertises local interface IPv4 addresses only.
func ValidatePublishAddress(raw string) (*url.URL, error) {
	u, err := ValidateURL(raw)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(u.Hostname()).To4()
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return nil, errors.New("publish URL must contain an active non-loopback local IPv4 address")
	}
	ips, err := ipForInterface()
	if err != nil {
		return nil, err
	}
	for _, local := range ips {
		if local.Equal(ip) {
			return u, nil
		}
	}
	return nil, errors.New("publish URL IP does not match a local LAN interface")
}

func instanceName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if len(name) == 0 || len(name) > 40 {
		return "", errors.New("invalid instance label")
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return "", errors.New("instance must be ASCII alphanumeric / - / _")
		}
	}
	return name + "." + Service, nil
}
func announceMessage(name string, port int, fingerprint string, ips []net.IP, ttl uint32) ([]byte, error) {
	inst, err := instanceName(name)
	if err != nil {
		return nil, err
	}
	if !FingerprintOK(fingerprint) {
		return nil, errors.New("invalid SHA-256 certificate fingerprint")
	}
	if port < 1 || port > 65535 {
		return nil, errors.New("invalid port")
	}
	host := strings.ReplaceAll(name, "_", "-") + ".local."
	var b bytes.Buffer
	b.Write(make([]byte, 12))
	p := b.Bytes()
	binary.BigEndian.PutUint16(p[2:4], 0x8400)
	binary.BigEndian.PutUint16(p[6:8], uint16(3+len(ips)))
	if err := appendRecord(&b, Service, 12, ttl, payloadName(inst)); err != nil {
		return nil, err
	}
	var srv bytes.Buffer
	_ = binary.Write(&srv, binary.BigEndian, uint16(0))
	_ = binary.Write(&srv, binary.BigEndian, uint16(0))
	_ = binary.Write(&srv, binary.BigEndian, uint16(port))
	_ = putName(&srv, host)
	if err := appendRecord(&b, inst, 33, ttl, srv.Bytes()); err != nil {
		return nil, err
	}
	txt, err := encodeTXT("txtvers=1", "tls=1", "fp="+strings.ToLower(fingerprint))
	if err != nil {
		return nil, err
	}
	if err := appendRecord(&b, inst, 16, ttl, txt); err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			if err := appendRecord(&b, host, 1, ttl, ipv4); err != nil {
				return nil, err
			}
		}
	}
	if b.Len() > maxMessage {
		return nil, errors.New("DNS response too large")
	}
	return b.Bytes(), nil
}

// Publish advertises an already running HTTPS backend. It does not listen on
// behalf of the backend, issue certificates, or change client trust settings.
func Publish(ctx context.Context, name string, port int, fingerprint string, listenIP net.IP) error {
	local, err := ipForInterface()
	if err != nil {
		return err
	}
	addr := listenIP.To4()
	if addr == nil {
		return errors.New("publisher requires a local IPv4 address")
	}
	found := false
	for _, ip := range local {
		if ip.Equal(addr) {
			found = true
			break
		}
	}
	if !found {
		return errors.New("publisher address is not a local LAN interface")
	}
	ips := []net.IP{addr}
	packet, err := announceMessage(name, port, fingerprint, ips, 120)
	if err != nil {
		return err
	}
	conn, err := net.ListenMulticastUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353})
	if err != nil {
		return fmt.Errorf("mDNS multicast listener: %w", err)
	}
	defer conn.Close()
	_ = conn.SetReadBuffer(65536)
	// Bind outgoing multicast to the same interface as the published HTTPS endpoint.
	// Otherwise multi-homed hosts can advertise on an unrelated network.
	sender, err := net.DialUDP("udp4", &net.UDPAddr{IP: addr}, &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353})
	if err != nil {
		return err
	}
	defer sender.Close()
	send := func(b []byte) error { _, e := sender.Write(b); return e }
	if err := send(packet); err != nil {
		return fmt.Errorf("mDNS initial advertisement: %w", err)
	}
	ticker := time.NewTicker(50 * time.Second)
	defer ticker.Stop()
	buf := make([]byte, maxMessage)
	for {
		if ctx.Err() != nil {
			goodbye, _ := announceMessage(name, port, fingerprint, ips, 0)
			_ = send(goodbye)
			return nil
		}
		_ = conn.SetReadDeadline(time.Now().Add(350 * time.Millisecond))
		n, addr, err := conn.ReadFromUDP(buf)
		if err == nil {
			qs, _, err := parsePacket(buf[:n])
			if err != nil {
				continue
			}
			for _, q := range qs {
				if strings.EqualFold(q.name, Service) && (q.typ == 12 || q.typ == 255) {
					_, _ = sender.Write(packet)
					break
				}
			}
			_ = addr
		}
		select {
		case <-ctx.Done():
			goodbye, _ := announceMessage(name, port, fingerprint, ips, 0)
			_ = send(goodbye)
			return nil
		case <-ticker.C:
			if err := send(packet); err != nil {
				return fmt.Errorf("mDNS refresh advertisement: %w", err)
			}
		default:
		}
	}
}

// ParseAdvertisement parses a DNS-SD reply, not an assertion of trust.
func ParseAdvertisement(p []byte) ([]Endpoint, error) {
	if len(p) < 12 || (binary.BigEndian.Uint16(p[2:4])&0x800f) != 0x8000 {
		return nil, errors.New("mDNS advertisement must be a successful DNS response")
	}
	_, rr, err := parsePacket(p)
	if err != nil {
		return nil, err
	}
	instances := map[string]bool{}
	srv := map[string]struct {
		port int
		host string
	}{}
	txt := map[string]map[string]string{}
	ips := map[string][]string{}
	for _, r := range rr {
		if r.ttl == 0 || (r.class&0x7fff) != 1 {
			continue
		}
		switch r.typ {
		case 12:
			if !strings.EqualFold(r.name, Service) {
				continue
			}
			pos := r.offset
			name, e := getName(p, &pos)
			if e == nil && pos == r.offset+len(r.data) {
				instances[strings.ToLower(name)] = true
			}
		case 33:
			if len(r.data) < 7 {
				continue
			}
			port := int(binary.BigEndian.Uint16(r.data[4:6]))
			pos := r.offset + 6
			target, e := getName(p, &pos)
			if e == nil && pos <= r.offset+len(r.data) {
				srv[strings.ToLower(r.name)] = struct {
					port int
					host string
				}{port, target}
			}
		case 16:
			fields, e := decodeTXT(r.data)
			if e == nil {
				txt[strings.ToLower(r.name)] = fields
			}
		case 1:
			if len(r.data) == 4 {
				ips[strings.ToLower(r.name)] = append(ips[strings.ToLower(r.name)], net.IP(r.data).String())
			}
		}
	}
	out := []Endpoint{}
	for inst := range instances {
		sv, ok := srv[inst]
		if !ok || sv.port == 0 {
			continue
		}
		fields := txt[inst]
		fp := fields["fp"]
		if fields["tls"] != "1" || fields["txtvers"] != "1" || !FingerprintOK(fp) {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(inst), "."+Service) {
			continue
		}
		for _, ip := range ips[strings.ToLower(sv.host)] {
			parsed := net.ParseIP(ip)
			if parsed == nil || parsed.IsUnspecified() || parsed.IsLoopback() || parsed.IsMulticast() || parsed.IsLinkLocalUnicast() || parsed.To4() == nil || parsed.Equal(net.IPv4bcast) {
				continue
			}
			out = append(out, Endpoint{Instance: strings.TrimSuffix(inst, "."+Service), Host: sv.host, Address: ip, Port: sv.port, Fingerprint: strings.ToLower(fp)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Instance+out[i].Address < out[j].Instance+out[j].Address })
	return out, nil
}
func Discover(ctx context.Context, duration time.Duration) ([]Endpoint, error) {
	if duration <= 0 || duration > 30*time.Second {
		return nil, errors.New("discovery duration must be 1..30s")
	}
	conn, err := net.ListenMulticastUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	sender, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353})
	if err != nil {
		return nil, err
	}
	defer sender.Close()
	_, err = sender.Write(buildQuery())
	if err != nil {
		return nil, err
	}
	end := time.Now().Add(duration)
	buf := make([]byte, maxMessage)
	found := map[string]Endpoint{}
	for time.Now().Before(end) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		limit := time.Now().Add(250 * time.Millisecond)
		if end.Before(limit) {
			limit = end
		}
		_ = conn.SetReadDeadline(limit)
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() {
				continue
			}
			return nil, err
		}
		items, err := ParseAdvertisement(buf[:n])
		if err != nil {
			continue
		}
		for _, item := range items {
			found[fmt.Sprintf("%s/%s/%d", item.Instance, item.Address, item.Port)] = item
		}
	}
	out := make([]Endpoint, 0, len(found))
	for _, v := range found {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Instance+out[i].Address < out[j].Instance+out[j].Address })
	return out, nil
}

// VerifyTLS requires a separately provisioned pin. A TXT fingerprint is *not*
// sufficient proof because DNS-SD advertisements have no authentication.
func VerifyTLS(ctx context.Context, rawURL, pin string) error {
	u, err := ValidateURL(rawURL)
	if err != nil {
		return err
	}
	if !FingerprintOK(pin) {
		return errors.New("explicit pinned SHA-256 certificate fingerprint is required")
	}
	expected, _ := hex.DecodeString(strings.ToLower(pin))
	dialer := net.Dialer{Timeout: 5 * time.Second}
	// This path deliberately replaces public-CA validation with an externally
	// pinned *leaf certificate*, not an unverified TXT advertisement.
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname(),
		InsecureSkipVerify: true, VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("TLS peer has no certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			if subtle.ConstantTimeCompare(sum[:], expected) != 1 {
				return errors.New("TLS certificate fingerprint mismatch")
			}
			return nil
		},
	}
	raw, err := dialer.DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return err
	}
	conn := tls.Client(raw, cfg)
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("pinned TLS handshake failed: %w", err)
	}
	return nil
}
