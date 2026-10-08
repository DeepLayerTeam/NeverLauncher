package ratelimit

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const fixedWindowScript = `local current=redis.call('INCR',KEYS[1]); if current==1 then redis.call('PEXPIRE',KEYS[1],ARGV[1]) end; local ttl=redis.call('PTTL',KEYS[1]); return {current,ttl}`

type RedisLimiter struct {
	address     string
	username    string
	password    string
	db          int
	tls         bool
	serverName  string
	dialTimeout time.Duration
}

func NewRedis(rawURL string) (*RedisLimiter, error) {
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
	return &RedisLimiter{address: address, username: username, password: password, db: db, tls: parsed.Scheme == "rediss", serverName: host, dialTimeout: 2 * time.Second}, nil
}

func (r *RedisLimiter) Backend() string { return "redis" }

func (r *RedisLimiter) Health(ctx context.Context) error {
	value, err := r.command(ctx, "PING")
	if err != nil {
		return err
	}
	pong, ok := value.(string)
	if !ok || !strings.EqualFold(pong, "PONG") {
		return fmt.Errorf("unexpected Redis PING response: %v", value)
	}
	return nil
}

func (r *RedisLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (Result, error) {
	if limit <= 0 || window <= 0 {
		return Result{Allowed: true, Limit: limit, Remaining: limit}, nil
	}
	sum := sha256.Sum256([]byte(key))
	redisKey := "neverlauncher:ratelimit:" + hex.EncodeToString(sum[:16])
	ttlMs := window.Milliseconds()
	value, err := r.command(ctx, "EVAL", fixedWindowScript, "1", redisKey, strconv.FormatInt(ttlMs, 10))
	if err != nil {
		return Result{}, err
	}
	items, ok := value.([]any)
	if !ok || len(items) != 2 {
		return Result{}, fmt.Errorf("unexpected Redis rate-limit response: %v", value)
	}
	count, ok1 := items[0].(int64)
	ttl, ok2 := items[1].(int64)
	if !ok1 || !ok2 {
		return Result{}, fmt.Errorf("invalid Redis rate-limit response: %v", value)
	}
	remaining := limit - int(count)
	if remaining < 0 {
		remaining = 0
	}
	if ttl < 0 {
		ttl = ttlMs
	}
	return Result{Allowed: count <= int64(limit), Limit: limit, Remaining: remaining, ResetAfter: time.Duration(ttl) * time.Millisecond}, nil
}

func (r *RedisLimiter) command(ctx context.Context, args ...string) (any, error) {
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
	value, err := readRESP(reader)
	if err != nil {
		return nil, fmt.Errorf("Redis command failed: %w", err)
	}
	return value, nil
}

func (r *RedisLimiter) dial(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: r.dialTimeout}
	if r.tls {
		return (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: r.serverName}}).DialContext(ctx, "tcp", r.address)
	}
	return dialer.DialContext(ctx, "tcp", r.address)
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
			value, err := readRESP(r)
			if err != nil {
				return nil, err
			}
			items = append(items, value)
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
