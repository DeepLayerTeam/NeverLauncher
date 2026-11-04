package httpapi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/officialminecraft"
	"gitflic.ru/skif4er/launcher/services/api/internal/texturepng"
)

// Tickets use AES-256-GCM, scoped to a live Never account and session. Neither
// Microsoft refresh credentials nor Minecraft tokens are persisted in local
// Yggdrasil profile tables, ServerBridge or the user's browser storage.
type officialState0257 struct {
	Kind             string `json:"kind"`
	User             string `json:"user"`
	Session          string `json:"session"`
	Expires          int64  `json:"expires"`
	DeviceCode       string `json:"deviceCode,omitempty"`
	Interval         int    `json:"interval,omitempty"`
	NextPoll         int64  `json:"nextPoll,omitempty"`
	MicrosoftRefresh string `json:"microsoftRefresh,omitempty"`
	// A successfully redeemed device grant must not be redeemed again if an
	// Xbox/Minecraft stage times out. These fields exist ONLY in AES-GCM flow
	// tickets, never in the JSON shown to Desktop's renderer.
	MicrosoftAccess        string `json:"microsoftAccess,omitempty"`
	MicrosoftAccessExpires int64  `json:"microsoftAccessExpires,omitempty"`
	MinecraftToken         string `json:"minecraftToken,omitempty"`
	MinecraftExpires       int64  `json:"minecraftExpires,omitempty"`
	UUID                   string `json:"uuid,omitempty"`
	Name                   string `json:"name,omitempty"`
}

func officialSeal0257(secret string, state officialState0257) (string, error) {
	if len(secret) < 24 {
		return "", errors.New("official token encryption key not configured")
	}
	key := sha256.Sum256([]byte("launcher/official-minecraft/aes-gcm/v1\x00" + secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	plain, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	sealed := aead.Seal(nil, nonce, plain, []byte("launcher-official-0257"))
	for i := range plain {
		plain[i] = 0
	}
	return base64.RawURLEncoding.EncodeToString(append(nonce, sealed...)), nil
}
func officialOpen0257(secret, ticket string) (officialState0257, error) {
	var state officialState0257
	if len(secret) < 24 || len(ticket) > 8192 {
		return state, errors.New("invalid official session")
	}
	raw, err := base64.RawURLEncoding.DecodeString(ticket)
	if err != nil {
		return state, errors.New("invalid official session")
	}
	key := sha256.Sum256([]byte("launcher/official-minecraft/aes-gcm/v1\x00" + secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return state, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return state, err
	}
	if len(raw) < aead.NonceSize()+aead.Overhead() {
		return state, errors.New("invalid official session")
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte("launcher-official-0257"))
	if err != nil {
		return state, errors.New("invalid official session")
	}
	defer func() {
		for i := range plain {
			plain[i] = 0
		}
	}()
	if err = json.Unmarshal(plain, &state); err != nil {
		return state, errors.New("invalid official session")
	}
	if state.Expires <= time.Now().Unix() || state.User == "" || state.Session == "" {
		return state, errors.New("expired official session")
	}
	return state, nil
}
func (s Server) officialActor0257(r *http.Request) (authClaims, error) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil || claims.Sub == "" || claims.SessionID == "" {
		return authClaims{}, errAuthRequired
	}
	user, err := s.Repo.GetUser(claims.Sub)
	if err != nil || user.Status == "disabled" {
		return authClaims{}, errAuthRequired
	}
	return claims, nil
}
func (s Server) officialRead0257(r *http.Request, kind string) (officialState0257, authClaims, error) {
	claims, err := s.officialActor0257(r)
	if err != nil {
		return officialState0257{}, claims, err
	}
	st, err := officialOpen0257(s.Config.AuthTokenSecret, r.Header.Get("X-Official-Minecraft-Session"))
	if err != nil || (st.Kind != kind && !(kind == "pending" && st.Kind == "redeemed")) || st.User != claims.Sub || st.Session != claims.SessionID {
		return officialState0257{}, claims, errAuthRequired
	}
	return st, claims, nil
}
func officialWrite0257(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, status, map[string]any{"apiVersion": apiContractVersion, "data": data})
}
func officialFail0257(w http.ResponseWriter, err error) {
	var upstream *officialminecraft.ServiceError
	switch {
	case errors.Is(err, officialminecraft.ErrDenied), errors.Is(err, officialminecraft.ErrUnlicensed):
		writeError(w, http.StatusForbidden, "official Minecraft account is not entitled or access was denied")
	case errors.Is(err, officialminecraft.ErrExpired):
		writeError(w, http.StatusUnauthorized, "Microsoft authorization expired")
	case errors.As(err, &upstream) && upstream.Status == 403 && upstream.Code == "invalid_app_registration":
		writeError(w, http.StatusForbidden, "Minecraft Services rejected the registered application ID; provider approval required")
	case errors.As(err, &upstream) && upstream.Status == 400 && (upstream.Code == "invalid_grant" || upstream.Code == "unauthorized_client"):
		writeError(w, http.StatusUnauthorized, "Microsoft OAuth grant expired, rejected or app redirect not permitted")
	case errors.As(err, &upstream) && upstream.Status == 404:
		writeError(w, http.StatusForbidden, "official Minecraft Java profile not available")
	case errors.As(err, &upstream) && upstream.Status == 401:
		writeError(w, http.StatusUnauthorized, "official Minecraft token expired or revoked")
	case errors.As(err, &upstream) && upstream.Status == 403:
		writeError(w, http.StatusForbidden, "Minecraft Services rejected operation")
	case errors.As(err, &upstream) && upstream.Status == 429:
		w.Header().Set("Retry-After", "30")
		writeError(w, http.StatusTooManyRequests, "Minecraft Services rate limit")
	default:
		writeError(w, http.StatusBadGateway, "official Minecraft service unavailable")
	}
}

var officialDevicePoll0257 = struct {
	sync.Mutex
	last map[[32]byte]time.Time
}{last: map[[32]byte]time.Time{}}

func officialPollingAllowed0257(code string, interval time.Duration) bool {
	key := sha256.Sum256([]byte(code))
	now := time.Now()
	officialDevicePoll0257.Lock()
	defer officialDevicePoll0257.Unlock()
	if last, ok := officialDevicePoll0257.last[key]; ok && now.Sub(last) < interval {
		return false
	}
	officialDevicePoll0257.last[key] = now
	if len(officialDevicePoll0257.last) > 4096 {
		for k, v := range officialDevicePoll0257.last {
			if now.Sub(v) > 30*time.Minute {
				delete(officialDevicePoll0257.last, k)
			}
		}
	}
	return true
}
func (s Server) officialBegin0257(w http.ResponseWriter, r *http.Request) {
	actor, err := s.officialActor0257(r)
	if err != nil {
		writeError(w, 401, "authentication required")
		return
	}
	policy, allowed := s.officialProviderPolicy02611(w, r, "device")
	if !allowed {
		return
	}
	if len(s.Config.AuthTokenSecret) < 24 {
		writeError(w, 503, "official Minecraft login is not configured")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	challenge, err := officialminecraft.New().Begin(ctx, policy.ClientID)
	if err != nil {
		officialFail0257(w, err)
		return
	}
	state := officialState0257{Kind: "pending", User: actor.Sub, Session: actor.SessionID, Expires: time.Now().Add(time.Duration(challenge.ExpiresIn) * time.Second).Unix(), DeviceCode: challenge.DeviceCode, Interval: challenge.Interval}
	ticket, err := officialSeal0257(s.Config.AuthTokenSecret, state)
	if err != nil {
		writeError(w, 503, "secure official session unavailable")
		return
	}
	officialWrite0257(w, 200, map[string]any{"verificationUri": challenge.VerificationURI, "userCode": challenge.UserCode, "message": challenge.Message, "intervalSeconds": challenge.Interval, "expiresIn": challenge.ExpiresIn, "flow": ticket})
}

// Temporary upstream failures after Microsoft token redemption must preserve
// the successful grant. Never repeat the one-use device_code redemption merely
// because Xbox Live, XSTS or Minecraft Services was briefly unavailable.
func officialTransient0257(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var upstream *officialminecraft.ServiceError
	if errors.As(err, &upstream) {
		return upstream.Status == http.StatusRequestTimeout || upstream.Status == http.StatusTooManyRequests || upstream.Status >= 500
	}
	// Malformed, unexpected or empty upstream responses can be transient.
	// Permission/grant failures above are ServiceError or sentinel errors.
	return !errors.Is(err, officialminecraft.ErrDenied) && !errors.Is(err, officialminecraft.ErrExpired) &&
		!errors.Is(err, officialminecraft.ErrUnlicensed)
}
func (s Server) officialContinue0257(w http.ResponseWriter, state officialState0257, delay int) {
	if delay < 5 {
		delay = 5
	}
	if delay > 3600 {
		delay = 3600
	}
	state.Interval = delay
	state.NextPoll = time.Now().Add(time.Duration(delay) * time.Second).Unix()
	sealed, err := officialSeal0257(s.Config.AuthTokenSecret, state)
	if err != nil {
		writeError(w, 503, "secure official session unavailable")
		return
	}
	w.Header().Set("Retry-After", strconv.Itoa(delay))
	officialWrite0257(w, http.StatusAccepted, map[string]any{
		"status": "pending", "flow": sealed, "intervalSeconds": delay,
		"expiresIn": max(int64(1), state.Expires-time.Now().Unix()),
	})
}
func (s Server) officialPoll0257(w http.ResponseWriter, r *http.Request) {
	policy, allowed := s.officialProviderPolicy02611(w, r, "device")
	if !allowed {
		return
	}
	if policy.ClientID == "" {
		writeError(w, 503, "official Minecraft login is not configured")
		return
	}
	st, actor, err := s.officialRead0257(r, "pending")
	if err != nil {
		writeError(w, 401, "invalid or expired official authorization flow")
		return
	}
	interval := time.Duration(st.Interval) * time.Second
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	now := time.Now()
	if now.Unix() < st.NextPoll || !officialPollingAllowed0257(st.DeviceCode, interval) {
		w.Header().Set("Retry-After", strconv.Itoa(max(5, st.Interval)))
		writeError(w, 429, "Microsoft authorization polling too frequent")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	client := officialminecraft.New()
	if st.Kind == "pending" {
		tokens, e := client.Complete(ctx, policy.ClientID, st.DeviceCode)
		if errors.Is(e, officialminecraft.ErrPending) || errors.Is(e, officialminecraft.ErrSlowDown) {
			if errors.Is(e, officialminecraft.ErrSlowDown) {
				st.Interval += 5
			}
			s.officialContinue0257(w, st, st.Interval)
			return
		}
		if e != nil {
			officialFail0257(w, e)
			return
		}
		st.Kind = "redeemed"
		st.MicrosoftAccess = tokens.AccessToken
		st.MicrosoftRefresh = tokens.RefreshToken
		st.MicrosoftAccessExpires = time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second).Unix()
		// The Device Code has already been consumed, but a short recovery window
		// is needed to finish the Xbox/Minecraft profile verification.
		if recoveryExpiry := time.Now().Add(5 * time.Minute).Unix(); st.Expires < recoveryExpiry {
			st.Expires = recoveryExpiry
		}
	}
	if st.MicrosoftAccess == "" {
		writeError(w, 401, "redeemed Microsoft authorization is incomplete")
		return
	}
	if st.MicrosoftAccessExpires <= time.Now().Add(60*time.Second).Unix() {
		if st.MicrosoftRefresh == "" {
			writeError(w, 401, "Microsoft reauthorization required")
			return
		}
		tokens, e := client.Refresh(ctx, policy.ClientID, st.MicrosoftRefresh)
		if e != nil {
			if officialTransient0257(e) {
				s.officialContinue0257(w, st, max(10, st.Interval))
				return
			}
			officialFail0257(w, e)
			return
		}
		st.MicrosoftAccess, st.MicrosoftRefresh = tokens.AccessToken, tokens.RefreshToken
		st.MicrosoftAccessExpires = time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second).Unix()
	}
	mc, err := client.Exchange(ctx, st.MicrosoftAccess)
	if err != nil {
		if officialTransient0257(err) {
			s.officialContinue0257(w, st, max(10, st.Interval))
			return
		}
		officialFail0257(w, err)
		return
	}
	profile, err := client.Profile(ctx, mc.AccessToken)
	if err != nil {
		if officialTransient0257(err) {
			s.officialContinue0257(w, st, max(10, st.Interval))
			return
		}
		officialFail0257(w, err)
		return
	}
	expiry := time.Now().Add(time.Duration(mc.ExpiresIn) * time.Second).Unix()
	if expiry > time.Now().Add(24*time.Hour).Unix() {
		expiry = time.Now().Add(24 * time.Hour).Unix()
	}
	linked := officialState0257{Kind: "linked", User: actor.Sub, Session: actor.SessionID,
		Expires: time.Now().Add(30 * 24 * time.Hour).Unix(), MicrosoftRefresh: st.MicrosoftRefresh,
		MinecraftToken: mc.AccessToken, MinecraftExpires: expiry, UUID: strings.ToLower(profile.ID), Name: profile.Name}
	if linked.MicrosoftRefresh == "" {
		linked.Expires = expiry
	}
	ticket, err := officialSeal0257(s.Config.AuthTokenSecret, linked)
	if err != nil {
		writeError(w, 503, "secure official session unavailable")
		return
	}
	officialWrite0257(w, 200, map[string]any{"realm": "official-minecraft", "profile": profile, "session": ticket, "expiresAt": linked.Expires})
}
func (s Server) officialAuthorized0257(w http.ResponseWriter, r *http.Request) (officialState0257, *officialminecraft.Client, bool) {
	policy, allowed := s.officialProviderPolicy02611(w, r, "")
	if !allowed {
		return officialState0257{}, nil, false
	}
	st, _, err := s.officialRead0257(r, "linked")
	if err != nil {
		writeError(w, 401, "official Minecraft session required")
		return st, nil, false
	}
	if st.MinecraftToken == "" || st.UUID == "" {
		writeError(w, 401, "official Minecraft session incomplete")
		return st, nil, false
	}
	client := officialminecraft.New()
	if st.MinecraftExpires <= time.Now().Add(60*time.Second).Unix() {
		if st.MicrosoftRefresh == "" {
			writeError(w, 401, "official Minecraft reauthorization required")
			return st, nil, false
		}
		ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
		defer cancel()
		tokens, e := client.Refresh(ctx, policy.ClientID, st.MicrosoftRefresh)
		if e != nil {
			officialFail0257(w, e)
			return st, nil, false
		}
		mc, e := client.Exchange(ctx, tokens.AccessToken)
		if e != nil {
			officialFail0257(w, e)
			return st, nil, false
		}
		profile, e := client.Profile(ctx, mc.AccessToken)
		if e != nil {
			officialFail0257(w, e)
			return st, nil, false
		}
		if !strings.EqualFold(profile.ID, st.UUID) {
			writeError(w, 403, "official account changed during refresh")
			return st, nil, false
		}
		st.MicrosoftRefresh = tokens.RefreshToken
		st.MinecraftToken = mc.AccessToken
		st.MinecraftExpires = time.Now().Add(time.Duration(mc.ExpiresIn) * time.Second).Unix()
		ticket, e := officialSeal0257(s.Config.AuthTokenSecret, st)
		if e != nil {
			writeError(w, 503, "secure official session unavailable")
			return st, nil, false
		}
		w.Header().Set("X-Official-Minecraft-Session", ticket)
	}
	return st, client, true
}
func (s Server) officialProfile0257(w http.ResponseWriter, r *http.Request) {
	st, client, ok := s.officialAuthorized0257(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	profile, err := client.Profile(ctx, st.MinecraftToken)
	if err != nil {
		officialFail0257(w, err)
		return
	}
	if !strings.EqualFold(profile.ID, st.UUID) {
		writeError(w, 403, "official Minecraft identity mismatch")
		return
	}
	officialWrite0257(w, 200, map[string]any{"realm": "official-minecraft", "profile": profile})
}
func (s Server) officialSkinUpload0257(w http.ResponseWriter, r *http.Request) {
	st, client, ok := s.officialAuthorized0257(w, r)
	if !ok {
		return
	}
	const bound = texturepng.MaxEncodedBytes + 16*1024
	r.Body = http.MaxBytesReader(w, r.Body, bound)
	mp, err := r.MultipartReader()
	if err != nil {
		writeError(w, 415, "multipart/form-data required")
		return
	}
	variant := ""
	var file []byte
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		part, e := mp.NextPart()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			writeError(w, 400, "invalid multipart payload")
			return
		}
		field := part.FormName()
		if seen[field] || (field != "variant" && field != "file") {
			part.Close()
			writeError(w, 400, "duplicate or unsupported multipart field")
			return
		}
		seen[field] = true
		b, e := io.ReadAll(io.LimitReader(part, texturepng.MaxEncodedBytes+1))
		part.Close()
		if e != nil || len(b) > texturepng.MaxEncodedBytes {
			writeError(w, 413, "skin exceeds upload limit")
			return
		}
		if field == "variant" {
			if len(b) > 10 {
				writeError(w, 400, "invalid variant")
				return
			}
			variant = string(b)
		} else {
			file = b
		}
	}
	if variant != "classic" && variant != "slim" {
		writeError(w, 400, "skin variant must be classic or slim")
		return
	}
	normalized, err := texturepng.Process(bytes.NewReader(file), "skin", variant)
	if err != nil {
		writeError(w, 422, "invalid Minecraft skin PNG")
		return
	}
	// Mojang's official upload API does not promise support for HD PNGs.
	if normalized.Width != 64 || (normalized.Height != 64 && normalized.Height != 32) {
		writeError(w, 422, "official skin must be 64x64 or classic 64x32")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	profile, err := client.UploadSkin(ctx, st.MinecraftToken, variant, normalized.PNG)
	if err != nil {
		officialFail0257(w, err)
		return
	}
	if !strings.EqualFold(profile.ID, st.UUID) {
		writeError(w, 502, "Minecraft Services returned another profile")
		return
	}
	profile, err = client.ConfirmTexture0395(ctx, st.MinecraftToken, st.UUID, "skin-upload", variant)
	if err != nil {
		officialFail0257(w, err)
		return
	}
	officialWrite0257(w, 200, map[string]any{"realm": "official-minecraft", "profile": profile})
}
func (s Server) officialResetSkin0257(w http.ResponseWriter, r *http.Request) {
	st, client, ok := s.officialAuthorized0257(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := client.ResetSkin(ctx, st.MinecraftToken); err != nil {
		officialFail0257(w, err)
		return
	}
	profile, err := client.ConfirmTexture0395(ctx, st.MinecraftToken, st.UUID, "skin-reset", "")
	if err != nil {
		officialFail0257(w, err)
		return
	}
	officialWrite0257(w, 200, map[string]any{"realm": "official-minecraft", "profile": profile})
}
func (s Server) officialCape0257(w http.ResponseWriter, r *http.Request) {
	st, client, ok := s.officialAuthorized0257(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if r.Method == "PUT" {
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		var req struct {
			CapeID string `json:"capeId"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil || req.CapeID == "" || len(req.CapeID) > 128 {
			writeError(w, 400, "capeId required")
			return
		}
		var extra any
		if dec.Decode(&extra) != io.EOF {
			writeError(w, 400, "one JSON object required")
			return
		}
		owned, err := client.Profile(ctx, st.MinecraftToken)
		if err != nil {
			officialFail0257(w, err)
			return
		}
		if !strings.EqualFold(owned.ID, st.UUID) {
			writeError(w, 403, "official Minecraft identity mismatch")
			return
		}
		found := false
		for _, cape := range owned.Capes {
			if cape.ID == req.CapeID {
				found = true
				break
			}
		}
		if !found {
			writeError(w, 403, "cape does not belong to official Minecraft account")
			return
		}
		updated, err := client.SelectCape(ctx, st.MinecraftToken, req.CapeID)
		if err != nil {
			officialFail0257(w, err)
			return
		}
		if !strings.EqualFold(updated.ID, st.UUID) {
			writeError(w, 502, "Minecraft Services returned another profile")
			return
		}
		updated, err = client.ConfirmTexture0395(ctx, st.MinecraftToken, st.UUID, "cape-select", req.CapeID)
		if err != nil {
			officialFail0257(w, err)
			return
		}
		officialWrite0257(w, 200, map[string]any{"realm": "official-minecraft", "profile": updated})
		return
	}
	if err := client.ResetCape(ctx, st.MinecraftToken); err != nil {
		officialFail0257(w, err)
		return
	}
	updated, err := client.ConfirmTexture0395(ctx, st.MinecraftToken, st.UUID, "cape-reset", "")
	if err != nil {
		officialFail0257(w, err)
		return
	}
	officialWrite0257(w, 200, map[string]any{"realm": "official-minecraft", "profile": updated})
}
func (s Server) officialLaunchCredentials0257(w http.ResponseWriter, r *http.Request) {
	st, client, ok := s.officialAuthorized0257(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	profile, err := client.Profile(ctx, st.MinecraftToken)
	if err != nil {
		officialFail0257(w, err)
		return
	}
	if !strings.EqualFold(profile.ID, st.UUID) {
		writeError(w, 403, "official Minecraft identity mismatch")
		return
	}
	officialWrite0257(w, 200, map[string]any{"realm": "official-minecraft", "username": profile.Name, "uuid": profile.ID, "accessToken": st.MinecraftToken, "userType": "msa", "authServerBaseUrl": ""})
}
