package ratelimit

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRedisLimiterHealthAndAtomicWindow(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			r := bufio.NewReader(conn)
			cmd, err := readTestRESPCommand(r)
			if err == nil && len(cmd) > 0 {
				switch strings.ToUpper(cmd[0]) {
				case "PING":
					fmt.Fprint(conn, "+PONG\r\n")
				case "EVAL":
					fmt.Fprint(conn, "*2\r\n:1\r\n:59999\r\n")
				}
			}
			conn.Close()
		}
	}()
	limiter, err := NewRedis("redis://" + ln.Addr().String() + "/0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := limiter.Health(ctx); err != nil {
		t.Fatal(err)
	}
	result, err := limiter.Allow(ctx, "auth|198.51.100.1", 20, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed || result.Remaining != 19 || result.ResetAfter <= 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	<-done
}

func readTestRESPCommand(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	count, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "*")))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		lengthLine, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(lengthLine, "$")))
		if err != nil {
			return nil, err
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		out = append(out, string(buf[:n]))
	}
	return out, nil
}
