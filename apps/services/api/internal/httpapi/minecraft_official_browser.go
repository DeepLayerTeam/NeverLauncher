package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/officialminecraft"
)

// OAuth code/verifier поступает исключительно от нативного клиента Desktop, а не
// от его renderer или браузера пользователя. Учётная запись привязывается к
// аутентифицированному сеансу Launcher до выдачи существующего непрозрачного билета.
// Client ID всегда берётся из собственной регистрации приложения на этом сервере.
type officialBrowserRequest0263 struct {
	Code        string `json:"code"`
	Verifier    string `json:"verifier"`
	RedirectURI string `json:"redirectUri"`
}

func validateOfficialBrowserRequest0263(v officialBrowserRequest0263) error {
	if err := officialminecraft.ValidateLoopbackRedirect(v.RedirectURI); err != nil {
		return err
	}
	if _, err := officialminecraft.PKCEChallenge(v.Verifier); err != nil {
		return err
	}
	if len(v.Code) < 8 || len(v.Code) > 4096 || strings.ContainsAny(v.Code, "\r\n\x00") {
		return errors.New("Некорректное значение: «код авторизации»")
	}
	return nil
}

func (s Server) officialBrowserConfig0263(w http.ResponseWriter, r *http.Request) {
	claims, err := s.officialActor0257(r)
	if err != nil {
		writeError(w, 401, "Требуется авторизация")
		return
	}
	policy, ok := s.officialProviderPolicy02611(w, r, "")
	if !ok {
		return
	}
	// Нативный Desktop должен доказать, что bearer принадлежит точно тому сеансу,
	// которым адресуются слоты хранилища секретов ОС. Иначе произвольный ID
	// сеанса из renderer мог бы читать Microsoft-учётные данные другого
	// локального пользователя.
	w.Header().Set("Cache-Control", "no-store")
	officialWrite0257(w, 200, map[string]any{"clientId": policy.ClientID, "enabled": policy.Enabled, "browserEnabled": policy.BrowserEnabled, "deviceEnabled": policy.DeviceEnabled, "issuer": policy.Issuer, "launcherSessionId": claims.SessionID, "launcherUserId": claims.Sub})
}

// provider — узкая подменяемая точка для проверки полной цепочки токенов локальной
// HTTP-фикстурой. В производстве всегда используется officialminecraft.New().
type officialBrowserProvider0263 interface {
	ExchangeAuthorizationCode(context.Context, string, string, string, string) (officialminecraft.OAuthTokens, error)
	Exchange(context.Context, string) (officialminecraft.MinecraftToken, error)
	Profile(context.Context, string) (officialminecraft.Profile, error)
}

func exchangeOfficialBrowser0263(ctx context.Context, provider officialBrowserProvider0263, clientID string, v officialBrowserRequest0263) (officialminecraft.OAuthTokens, officialminecraft.MinecraftToken, officialminecraft.Profile, error) {
	if err := officialminecraft.ValidateClientID(clientID); err != nil {
		return officialminecraft.OAuthTokens{}, officialminecraft.MinecraftToken{}, officialminecraft.Profile{}, err
	}
	if err := validateOfficialBrowserRequest0263(v); err != nil {
		return officialminecraft.OAuthTokens{}, officialminecraft.MinecraftToken{}, officialminecraft.Profile{}, err
	}
	tokens, err := provider.ExchangeAuthorizationCode(ctx, clientID, v.RedirectURI, v.Code, v.Verifier)
	if err != nil {
		return officialminecraft.OAuthTokens{}, officialminecraft.MinecraftToken{}, officialminecraft.Profile{}, err
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		return officialminecraft.OAuthTokens{}, officialminecraft.MinecraftToken{}, officialminecraft.Profile{}, errors.New("Отсутствует: «токен доступа или обновления Microsoft»")
	}
	mc, err := provider.Exchange(ctx, tokens.AccessToken)
	if err != nil {
		return officialminecraft.OAuthTokens{}, officialminecraft.MinecraftToken{}, officialminecraft.Profile{}, err
	}
	if mc.AccessToken == "" || mc.ExpiresIn <= 0 {
		return officialminecraft.OAuthTokens{}, officialminecraft.MinecraftToken{}, officialminecraft.Profile{}, errors.New("Отсутствует: «токен доступа Minecraft»")
	}
	profile, err := provider.Profile(ctx, mc.AccessToken)
	if err != nil {
		return officialminecraft.OAuthTokens{}, officialminecraft.MinecraftToken{}, officialminecraft.Profile{}, err
	}
	if !validOfficialProfile0263(profile) {
		return officialminecraft.OAuthTokens{}, officialminecraft.MinecraftToken{}, officialminecraft.Profile{}, errors.New("Профиль Minecraft Java не прошёл проверку")
	}
	return tokens, mc, profile, nil
}

func validOfficialProfile0263(profile officialminecraft.Profile) bool {
	if len(profile.ID) != 32 || len(profile.Name) < 3 || len(profile.Name) > 16 {
		return false
	}
	for _, c := range profile.ID {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	for _, c := range profile.Name {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_') {
			return false
		}
	}
	return true
}

func (s Server) officialBrowserExchange0263(w http.ResponseWriter, r *http.Request) {
	actor, err := s.officialActor0257(r)
	if err != nil {
		writeError(w, 401, "Требуется авторизация")
		return
	}
	policy, allowed := s.officialProviderPolicy02611(w, r, "browser")
	if !allowed {
		return
	}
	if len(s.Config.AuthTokenSecret) < 24 {
		writeError(w, 503, "Регистрация собственного официального приложения не настроена")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var v officialBrowserRequest0263
	if err := decoder.Decode(&v); err != nil {
		writeError(w, 400, "Недопустимые данные кода авторизации браузера")
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		writeError(w, 400, "Неожиданные данные ответа браузера")
		return
	}
	if err := validateOfficialBrowserRequest0263(v); err != nil {
		writeError(w, 400, "Недопустимые учётные данные обратного вызова браузера")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 70*time.Second)
	defer cancel()
	tokens, mc, profile, err := exchangeOfficialBrowser0263(ctx, officialminecraft.New(), policy.ClientID, v)
	if err != nil {
		officialFail0257(w, err)
		return
	}
	expiry := time.Now().Add(time.Duration(mc.ExpiresIn) * time.Second).Unix()
	if expiry > time.Now().Add(24*time.Hour).Unix() {
		expiry = time.Now().Add(24 * time.Hour).Unix()
	}
	linked := officialState0257{
		Kind: "linked", User: actor.Sub, Session: actor.SessionID,
		Expires:          time.Now().Add(30 * 24 * time.Hour).Unix(),
		MicrosoftRefresh: tokens.RefreshToken, MinecraftToken: mc.AccessToken,
		MinecraftExpires: expiry, UUID: strings.ToLower(profile.ID), Name: profile.Name,
	}
	ticket, err := officialSeal0257(s.Config.AuthTokenSecret, linked)
	if err != nil {
		writeError(w, 503, "Защищённая официальная сессия недоступна")
		return
	}
	officialWrite0257(w, 200, map[string]any{
		"realm": "official-minecraft", "profile": profile, "session": ticket, "expiresAt": linked.Expires,
	})
}
