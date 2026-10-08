package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type authTokenHeader118 struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

func (s Server) authTokenIssuer118() string {
	v := strings.TrimRight(strings.TrimSpace(s.Config.AuthTokenIssuer), "/")
	if v == "" {
		v = strings.TrimRight(strings.TrimSpace(s.Config.PublicURL), "/")
	}
	if v == "" {
		v = "neverlauncher"
	}
	return v
}

func (s Server) authTokenAudience118() string {
	if v := strings.TrimSpace(s.Config.AuthTokenAudience); v != "" {
		return v
	}
	return "neverlauncher-api"
}

func (s Server) authTokenKeys118() (string, map[string]string, error) {
	active := strings.TrimSpace(s.Config.AuthTokenActiveKID)
	if active == "" {
		active = "primary"
	}
	keys := map[string]string{}
	if raw := strings.TrimSpace(s.Config.AuthTokenKeysJSON); raw != "" {
		if err := json.Unmarshal([]byte(raw), &keys); err != nil {
			return "", nil, fmt.Errorf("invalid auth token keyring: %w", err)
		}
	}
	if len(keys) == 0 {
		keys[active] = strings.TrimSpace(s.Config.AuthTokenSecret)
	}
	for kid, secret := range keys {
		nk := strings.TrimSpace(kid)
		sv := strings.TrimSpace(secret)
		if nk == "" || sv == "" {
			return "", nil, errors.New("auth token keyring contains empty kid/secret")
		}
		if nk != kid {
			delete(keys, kid)
			keys[nk] = sv
		} else {
			keys[kid] = sv
		}
	}
	if strings.TrimSpace(keys[active]) == "" {
		return "", nil, fmt.Errorf("active auth token kid %q is absent from keyring", active)
	}
	return active, keys, nil
}

func signJWT118(input, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(input))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s Server) encodeAccessToken118(claims authClaims) (string, error) {
	kid, keys, err := s.authTokenKeys118()
	if err != nil {
		return "", err
	}
	headerRaw, err := json.Marshal(authTokenHeader118{Alg: "HS256", Typ: "JWT", Kid: kid})
	if err != nil {
		return "", err
	}
	claims.Iss = s.authTokenIssuer118()
	claims.Aud = s.authTokenAudience118()
	if strings.TrimSpace(claims.JTI) == "" {
		claims.JTI, err = randomToken("ati")
		if err != nil {
			return "", err
		}
	}
	payloadRaw, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	head := base64.RawURLEncoding.EncodeToString(headerRaw)
	body := base64.RawURLEncoding.EncodeToString(payloadRaw)
	input := head + "." + body
	return input + "." + signJWT118(input, keys[kid]), nil
}

func (s Server) decodeAccessToken118(token string) (authClaims, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return authClaims{}, errAuthRequired
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return authClaims{}, errAuthRequired
	}
	var header authTokenHeader118
	if json.Unmarshal(headerRaw, &header) != nil || header.Alg != "HS256" || header.Typ != "JWT" || strings.TrimSpace(header.Kid) == "" {
		return authClaims{}, errAuthRequired
	}
	_, keys, err := s.authTokenKeys118()
	if err != nil {
		return authClaims{}, errAuthRequired
	}
	secret, ok := keys[header.Kid]
	if !ok {
		return authClaims{}, errAuthRequired
	}
	expected := signJWT118(parts[0]+"."+parts[1], secret)
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return authClaims{}, errAuthRequired
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return authClaims{}, errAuthRequired
	}
	var claims authClaims
	if json.Unmarshal(payload, &claims) != nil {
		return authClaims{}, errAuthRequired
	}
	now := time.Now().UTC().Unix()
	if claims.Iss != s.authTokenIssuer118() || claims.Aud != s.authTokenAudience118() || claims.Sub == "" || claims.SessionID == "" || claims.JTI == "" || claims.TokenUse != "access" || claims.Exp <= now || claims.Iat > now+60 {
		return authClaims{}, errAuthRequired
	}
	return claims, nil
}
