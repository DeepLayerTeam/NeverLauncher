// Package copilotproof binds a short-lived preview to the exact validated payload.
package copilotproof

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

const Prefix = "copilot:"
const TTL = 120 * time.Second

type Binding struct{ User, Session, Kind, Project, Resource, Key string }

func signature(secret string, b Binding, raw []byte, expiry int64) ([]byte, bool) {
	if secret == "" || b.User == "" || b.Session == "" || b.Project == "" || b.Resource == "" || !strings.HasPrefix(b.Key, Prefix) {
		return nil, false
	}
	// PostgreSQL JSONB may reorder fields. Preserve exact numeric values.
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var payload any
	if d.Decode(&payload) != nil {
		return nil, false
	}
	canonical, err := json.Marshal(struct {
		Domain  string
		Binding Binding
		Expiry  int64
		Payload any
	}{"neverlauncher/copilot-preview/v1", b, expiry, payload})
	if err != nil {
		return nil, false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(canonical)
	return mac.Sum(nil), true
}
func Issue(secret string, b Binding, raw []byte, now time.Time) (string, bool) {
	exp := now.Add(TTL).Unix()
	sig, ok := signature(secret, b, raw, exp)
	if !ok {
		return "", false
	}
	return strconv.FormatInt(exp, 10) + "." + base64.RawURLEncoding.EncodeToString(sig), true
}
func Verify(secret string, b Binding, raw []byte, ticket string, now time.Time) bool {
	if len(ticket) > 128 {
		return false
	}
	expStr, encoded, ok := strings.Cut(ticket, ".")
	if !ok {
		return false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || exp <= now.Unix() || exp > now.Add(TTL).Unix() {
		return false
	}
	got, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	want, ok := signature(secret, b, raw, exp)
	return ok && hmac.Equal(got, want)
}
