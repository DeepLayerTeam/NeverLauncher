package serverbridgeha

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	acquireLeaseScript = `local v=redis.call('GET',KEYS[1]); if not v then local ok=redis.call('SET',KEYS[1],ARGV[1],'NX','PX',ARGV[2]); if ok then return 1 else return 0 end end; if v==ARGV[1] then redis.call('PEXPIRE',KEYS[1],ARGV[2]); return 1 end; return 0`
	releaseLeaseScript = `local v=redis.call('GET',KEYS[1]); if v==ARGV[1] then return redis.call('DEL',KEYS[1]) end; return 0`
)

// Coordinator is the ephemeral distributed fence used in addition to PostgreSQL's
// durable row lease. Losing Redis never causes control to fail open.
type Coordinator interface {
	Backend() string
	Health(context.Context) error
	TouchChannel(context.Context, ChannelPresence, time.Duration) error
	AcquireCommandLease(context.Context, string, string, string, string, time.Duration) (bool, error)
	VerifyCommandLease(context.Context, string, string, string, string) (bool, error)
	ReleaseCommandLease(context.Context, string, string, string, string) error
}

type ChannelPresence struct {
	ReplicaID      string
	ServerID       string
	RuntimeID      string
	ChannelID      string
	ResumeAfter    int64
	BackendAddress string
}

type RedisCoordinator struct {
	address     string
	username    string
	password    string
	db          int
	tls         bool
	serverName  string
	dialTimeout time.Duration
}

func NewRedis(rawURL string) (*RedisCoordinator, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, errors.New("Redis URL is empty")
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "redis://" + rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid Redis URL: %w", err)
	}
	if parsed.Scheme != "redis" && parsed.Scheme != "rediss" {
		return nil, fmt.Errorf("unsupported Redis scheme %q", parsed.Scheme)
	}
	address := parsed.Host
	if !strings.Contains(address, ":") {
		address += ":6379"
	}
	db := 0
	if value := strings.Trim(strings.TrimSpace(parsed.Path), "/"); value != "" {
		db, err = strconv.Atoi(value)
		if err != nil || db < 0 {
			return nil, fmt.Errorf("invalid Redis database %q", value)
		}
	}
	username, password := "", ""
	if parsed.User != nil {
		username = parsed.User.Username()
		password, _ = parsed.User.Password()
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid Redis address %q: %w", address, err)
	}
	return &RedisCoordinator{address: address, username: username, password: password, db: db, tls: parsed.Scheme == "rediss", serverName: host, dialTimeout: 2 * time.Second}, nil
}

func (r *RedisCoordinator) Backend() string { return "redis" }

func (r *RedisCoordinator) Health(ctx context.Context) error {
	v, err := r.command(ctx, "PING")
	if err != nil {
		return err
	}
	if s, ok := v.(string); !ok || !strings.EqualFold(s, "PONG") {
		return fmt.Errorf("unexpected Redis PING response: %v", v)
	}
	return nil
}

func (r *RedisCoordinator) TouchChannel(ctx context.Context, p ChannelPresence, ttl time.Duration) error {
	if ttl < 5*time.Second {
		ttl = 5 * time.Second
	}
	key := "neverlauncher:serverbridge:ha:channel:" + safePart(p.ServerID) + ":" + safePart(p.RuntimeID) + ":" + safePart(p.ChannelID)
	value := strings.Join([]string{safePart(p.ReplicaID), strconv.FormatInt(p.ResumeAfter, 10), safePart(p.BackendAddress)}, "|")
	_, err := r.command(ctx, "SET", key, value, "PX", strconv.FormatInt(ttl.Milliseconds(), 10))
	return err
}

func (r *RedisCoordinator) AcquireCommandLease(ctx context.Context, serverID, commandID, owner, token string, ttl time.Duration) (bool, error) {
	if ttl < 5*time.Second {
		ttl = 5 * time.Second
	}
	value := leaseValue(owner, token)
	v, err := r.command(ctx, "EVAL", acquireLeaseScript, "1", commandKey(serverID, commandID), value, strconv.FormatInt(ttl.Milliseconds(), 10))
	if err != nil {
		return false, err
	}
	n, ok := v.(int64)
	if !ok {
		return false, fmt.Errorf("unexpected Redis lease response: %v", v)
	}
	return n == 1, nil
}

func (r *RedisCoordinator) VerifyCommandLease(ctx context.Context, serverID, commandID, owner, token string) (bool, error) {
	v, err := r.command(ctx, "GET", commandKey(serverID, commandID))
	if err != nil {
		return false, err
	}
	if v == nil {
		return false, nil
	}
	s, ok := v.(string)
	return ok && s == leaseValue(owner, token), nil
}

func (r *RedisCoordinator) ReleaseCommandLease(ctx context.Context, serverID, commandID, owner, token string) error {
	_, err := r.command(ctx, "EVAL", releaseLeaseScript, "1", commandKey(serverID, commandID), leaseValue(owner, token))
	return err
}

func commandKey(serverID, commandID string) string {
	return "neverlauncher:serverbridge:ha:command:" + safePart(serverID) + ":" + safePart(commandID)
}
func leaseValue(owner, token string) string { return safePart(owner) + "|" + safePart(token) }
func safePart(v string) string {
	v = strings.TrimSpace(v)
	var b strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (r *RedisCoordinator) command(ctx context.Context, args ...string) (any, error) {
	conn, err := r.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	}
	reader := bufio.NewReader(conn)
	if r.password != "" {
		auth := []string{"AUTH"}
		if r.username != "" {
			auth = append(auth, r.username)
		}
		auth = append(auth, r.password)
		if err := writeRESP(conn, auth...); err != nil {
			return nil, fmt.Errorf("Redis AUTH write failed: %w", err)
		}
		if _, err := readRESP(reader); err != nil {
			return nil, fmt.Errorf("Redis AUTH failed: %w", err)
		}
	}
	if r.db != 0 {
		if err := writeRESP(conn, "SELECT", strconv.Itoa(r.db)); err != nil {
			return nil, fmt.Errorf("Redis SELECT write failed: %w", err)
		}
		if _, err := readRESP(reader); err != nil {
			return nil, fmt.Errorf("Redis SELECT failed: %w", err)
		}
	}
	if err := writeRESP(conn, args...); err != nil {
		return nil, fmt.Errorf("Redis command write failed: %w", err)
	}
	v, err := readRESP(reader)
	if err != nil {
		return nil, fmt.Errorf("Redis command failed: %w", err)
	}
	return v, nil
}

func (r *RedisCoordinator) dial(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: r.dialTimeout}
	if r.tls {
		return (&tls.Dialer{NetDialer: d, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: r.serverName}}).DialContext(ctx, "tcp", r.address)
	}
	return d.DialContext(ctx, "tcp", r.address)
}

func writeRESP(w io.Writer, args ...string) error {
	if _, err := fmt.Fprintf(w, "*%d\r\n", len(args)); err != nil {
		return err
	}
	for _, arg := range args {
		if _, err := fmt.Fprintf(w, "$%d\r\n%s\r\n", len(arg), arg); err != nil {
			return err
		}
	}
	return nil
}
func readRESP(r *bufio.Reader) (any, error) {
	prefix, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	line, err := readLine(r)
	if err != nil {
		return nil, err
	}
	switch prefix {
	case '+':
		return line, nil
	case '-':
		return nil, errors.New(line)
	case ':':
		return strconv.ParseInt(line, 10, 64)
	case '$':
		n, err := strconv.Atoi(line)
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		if string(buf[n:]) != "\r\n" {
			return nil, errors.New("malformed Redis bulk string")
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(line)
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, nil
		}
		items := make([]any, 0, n)
		for i := 0; i < n; i++ {
			v, err := readRESP(r)
			if err != nil {
				return nil, err
			}
			items = append(items, v)
		}
		return items, nil
	default:
		return nil, fmt.Errorf("unknown Redis RESP prefix %q", prefix)
	}
}
func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if !strings.HasSuffix(line, "\r\n") {
		return "", errors.New("malformed Redis response")
	}
	return strings.TrimSuffix(line, "\r\n"), nil
}
