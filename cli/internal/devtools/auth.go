package devtools

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const TestTokenPrefix = "nltest.v1."

type TestClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Scope     []string `json:"scope"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
	ID        string   `json:"jti"`
}
type AuthEvent struct {
	Sequence uint64 `json:"sequence"`
	Type     string `json:"type"`
	Subject  string `json:"subject"`
	At       string `json:"at"`
}
type FixtureServer struct {
	secret   [32]byte
	control  [32]byte
	password [24]byte
	user     string
	mu       sync.Mutex
	events   []AuthEvent
	revoked  map[string]bool
	next     uint64
	now      func() time.Time
}

func NewFixtureServer(user string) (*FixtureServer, error) {
	if user == "" || len(user) > 64 || strings.ContainsAny(user, " \t\r\n/:\\") {
		return nil, errors.New("invalid fixture username")
	}
	f := &FixtureServer{user: user, revoked: make(map[string]bool), now: time.Now}
	if _, e := rand.Read(f.secret[:]); e != nil {
		return nil, e
	}
	if _, e := rand.Read(f.control[:]); e != nil {
		return nil, e
	}
	if _, e := rand.Read(f.password[:]); e != nil {
		return nil, e
	}
	return f, nil
}
func (f *FixtureServer) ControlToken() string {
	return base64.RawURLEncoding.EncodeToString(f.control[:])
}
func (f *FixtureServer) Password() string { return base64.RawURLEncoding.EncodeToString(f.password[:]) }
func (f *FixtureServer) User() string     { return f.user }
func (f *FixtureServer) addEvent(typ, sub string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	f.events = append(f.events, AuthEvent{Sequence: f.next, Type: typ, Subject: sub, At: f.now().UTC().Format(time.RFC3339Nano)})
	if len(f.events) > 256 {
		f.events = f.events[len(f.events)-256:]
	}
}
func (f *FixtureServer) Issue(sub string, scopes []string, ttl time.Duration) (string, error) {
	if sub == "" || len(sub) > 128 || ttl <= 0 || ttl > 15*time.Minute {
		return "", errors.New("invalid test identity or TTL")
	}
	for _, s := range scopes {
		if s == "" || len(s) > 64 || strings.ContainsAny(s, " \t\r\n") {
			return "", errors.New("invalid test scope")
		}
	}
	if len(scopes) > 16 {
		return "", errors.New("too many test scopes")
	}
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return "", e
	}
	now := f.now()
	payload, _ := json.Marshal(TestClaims{Issuer: "launcher.devtools.test-only", Subject: sub, Scope: scopes, IssuedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix(), ID: base64.RawURLEncoding.EncodeToString(nonce[:])})
	p := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, f.secret[:])
	mac.Write([]byte(TestTokenPrefix + p))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	f.addEvent("auth.identity.issued", sub)
	return TestTokenPrefix + p + "." + sig, nil
}
func (f *FixtureServer) Verify(token string) (TestClaims, error) {
	var claims TestClaims
	if !strings.HasPrefix(token, TestTokenPrefix) || len(token) > 4096 {
		return claims, errors.New("test token required")
	}
	parts := strings.Split(strings.TrimPrefix(token, TestTokenPrefix), ".")
	if len(parts) != 2 {
		return claims, errors.New("malformed test token")
	}
	mac := hmac.New(sha256.New, f.secret[:])
	mac.Write([]byte(TestTokenPrefix + parts[0]))
	sig, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil || !hmac.Equal(sig, mac.Sum(nil)) {
		return claims, errors.New("invalid test signature")
	}
	payload, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil || json.Unmarshal(payload, &claims) != nil {
		return claims, errors.New("invalid test payload")
	}
	if claims.Issuer != "launcher.devtools.test-only" || claims.ExpiresAt <= f.now().Unix() || claims.IssuedAt > f.now().Unix()+1 {
		return claims, errors.New("expired or incorrect test identity")
	}
	f.mu.Lock()
	revoked := f.revoked[claims.ID]
	f.mu.Unlock()
	if revoked {
		return claims, errors.New("revoked test identity")
	}
	return claims, nil
}
func (f *FixtureServer) controlOK(r *http.Request) bool {
	given := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	raw, e := base64.RawURLEncoding.DecodeString(given)
	return e == nil && len(raw) == 32 && subtle.ConstantTimeCompare(raw, f.control[:]) == 1
}
func writeFixtureJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fixtureDecode(r *http.Request, v any) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return errors.New("expected application/json")
	}
	d := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 8192))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return errors.New("trailing or malformed JSON")
	}
	return nil
}
func (f *FixtureServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /fixture/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeFixtureJSON(w, 200, map[string]any{"mode": "test-only", "issuer": "launcher.devtools.test-only"})
	})
	mux.HandleFunc("POST /fixture/v1/login", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if e := fixtureDecode(r, &req); e != nil || len(req.Username) > 64 {
			writeFixtureJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		pass, e := base64.RawURLEncoding.DecodeString(req.Password)
		if e != nil || subtle.ConstantTimeCompare(pass, f.password[:]) != 1 || req.Username != f.user {
			f.addEvent("auth.login.rejected", req.Username)
			writeFixtureJSON(w, 401, map[string]string{"error": "invalid fixture credentials"})
			return
		}
		tok, e := f.Issue(f.user, []string{"test:player"}, 5*time.Minute)
		if e != nil {
			writeFixtureJSON(w, 500, map[string]string{"error": "internal error"})
			return
		}
		f.addEvent("auth.login.succeeded", f.user)
		writeFixtureJSON(w, 200, map[string]any{"accessToken": tok, "tokenType": "TestOnly", "expiresIn": 300})
	})
	mux.HandleFunc("POST /fixture/v1/issue", func(w http.ResponseWriter, r *http.Request) {
		if !f.controlOK(r) {
			writeFixtureJSON(w, 403, map[string]string{"error": "test control token required"})
			return
		}
		var req struct {
			Subject    string   `json:"subject"`
			Scopes     []string `json:"scopes"`
			TTLSeconds int      `json:"ttlSeconds"`
		}
		if e := fixtureDecode(r, &req); e != nil || len(req.Subject) > 128 {
			writeFixtureJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		tok, e := f.Issue(req.Subject, req.Scopes, time.Duration(req.TTLSeconds)*time.Second)
		if e != nil {
			writeFixtureJSON(w, 422, map[string]string{"error": e.Error()})
			return
		}
		writeFixtureJSON(w, 200, map[string]string{"accessToken": tok})
	})
	mux.HandleFunc("POST /fixture/v1/introspect", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token string `json:"token"`
		}
		if fixtureDecode(r, &req) != nil {
			writeFixtureJSON(w, 400, map[string]any{"active": false})
			return
		}
		c, e := f.Verify(req.Token)
		if e != nil {
			writeFixtureJSON(w, 200, map[string]any{"active": false})
			return
		}
		writeFixtureJSON(w, 200, map[string]any{"active": true, "claims": c})
	})
	mux.HandleFunc("POST /fixture/v1/revoke", func(w http.ResponseWriter, r *http.Request) {
		if !f.controlOK(r) {
			writeFixtureJSON(w, 403, map[string]string{"error": "control token required"})
			return
		}
		var req struct {
			Token string `json:"token"`
		}
		if fixtureDecode(r, &req) != nil {
			writeFixtureJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		c, e := f.Verify(req.Token)
		if e != nil {
			writeFixtureJSON(w, 404, map[string]string{"error": "unknown test token"})
			return
		}
		f.mu.Lock()
		f.revoked[c.ID] = true
		f.mu.Unlock()
		f.addEvent("auth.identity.revoked", c.Subject)
		writeFixtureJSON(w, 200, map[string]bool{"revoked": true})
	})
	mux.HandleFunc("GET /fixture/v1/events", func(w http.ResponseWriter, r *http.Request) {
		if !f.controlOK(r) {
			writeFixtureJSON(w, 403, map[string]string{"error": "control token required"})
			return
		}
		after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		f.mu.Lock()
		events := make([]AuthEvent, 0)
		for _, v := range f.events {
			if v.Sequence > after {
				events = append(events, v)
			}
		}
		f.mu.Unlock()
		writeFixtureJSON(w, 200, map[string]any{"events": events})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "" {
			http.Error(w, "bad host", 400)
			return
		}
		mux.ServeHTTP(w, r)
	})
}
func ListenFixture(addr string, f *FixtureServer) (net.Listener, error) {
	host, _, e := net.SplitHostPort(addr)
	if e != nil {
		return nil, e
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("fixture must bind a numeric loopback address, got %q", host)
	}
	return net.Listen("tcp", addr)
}
