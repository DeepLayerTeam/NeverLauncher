package officialminecraft

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var publicClientID = regexp.MustCompile(`(?i)^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

// ValidateClientID не допускает незаметного перехода POC на публичную
// регистрацию другого лаунчера. Client ID необходимо указывать явно.
func ValidateClientID(clientID string) error {
	if !publicClientID.MatchString(clientID) || strings.EqualFold(clientID, "00000000-0000-0000-0000-000000000000") {
		return errors.New("Требуется: «действительный UUID приложения (клиента)»")
	}
	return nil
}

// ValidateLoopbackRedirect разрешает коды авторизации только получателю loopback.
// Вызывающий ОБЯЗАН проверить OAuth state до обмена кода.
func ValidateLoopbackRedirect(redirect string) error {
	u, err := url.Parse(redirect)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Port() == "" || u.Path != "/minecraft-poc/callback" {
		return errors.New("Адрес перенаправления должен быть http://localhost:<port>/minecraft-poc/callback (или 127.0.0.1)")
	}
	if u.Hostname() != "localhost" && net.ParseIP(u.Hostname()) == nil {
		return errors.New("Хост перенаправления не является loopback-адресом")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && !ip.IsLoopback() {
		return errors.New("Хост перенаправления не является loopback-адресом")
	}
	if u.Port() == "0" {
		return errors.New("В адресе перенаправления должен быть указан порт")
	}
	return nil
}

func PKCEChallenge(verifier string) (string, error) {
	if len(verifier) < 43 || len(verifier) > 128 || !regexp.MustCompile(`^[A-Za-z0-9._~-]+$`).MatchString(verifier) {
		return "", errors.New("Некорректное значение: «проверочный секрет PKCE»")
	}
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

func (c *Client) AuthorizationURL(clientID, redirect, state, challenge string) (string, error) {
	if err := ValidateClientID(clientID); err != nil {
		return "", err
	}
	if err := ValidateLoopbackRedirect(redirect); err != nil {
		return "", err
	}
	if len(state) < 32 || len(state) > 256 || !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(state) {
		return "", errors.New("Некорректное значение: OAuth состояние")
	}
	if len(challenge) != 43 || !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(challenge) {
		return "", errors.New("Недопустимый проверочный код S256")
	}
	v := url.Values{
		"client_id": {clientID}, "response_type": {"code"}, "redirect_uri": {redirect},
		"response_mode": {"query"}, "scope": {"XboxLive.signin offline_access"},
		"state": {state}, "code_challenge_method": {"S256"}, "code_challenge": {challenge},
	}
	return fmt.Sprintf("%s/authorize?%s", c.microsoft, v.Encode()), nil
}

func (c *Client) ExchangeAuthorizationCode(ctx context.Context, clientID, redirect, code, verifier string) (OAuthTokens, error) {
	if err := ValidateClientID(clientID); err != nil {
		return OAuthTokens{}, err
	}
	if err := ValidateLoopbackRedirect(redirect); err != nil {
		return OAuthTokens{}, err
	}
	if len(code) == 0 || len(code) > 4096 || strings.ContainsAny(code, "\r\n") {
		return OAuthTokens{}, errors.New("Некорректный код OAuth")
	}
	if _, err := PKCEChallenge(verifier); err != nil {
		return OAuthTokens{}, err
	}
	body, ct := form(url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"code": {code}, "code_verifier": {verifier}, "scope": {"XboxLive.signin offline_access"},
	})
	var result OAuthTokens
	if err := c.request(ctx, "POST", c.microsoft+"/token", "", ct, body, &result); err != nil {
		return OAuthTokens{}, err
	}
	if result.AccessToken == "" || !strings.EqualFold(result.TokenType, "Bearer") || result.ExpiresIn <= 0 {
		return OAuthTokens{}, errors.New("Неполный ответ с токеном по коду авторизации Microsoft")
	}
	return result, nil
}

// EntitlementCount возвращает число прав доступа, видимых Minecraft Services, а
// не утверждение о покупке. Для учётных записей Java/Game Pass живой профиль
// может быть доступен даже при нуле элементов mcstore.
func (c *Client) EntitlementCount(ctx context.Context, token string) (int, error) {
	var reply struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if token == "" {
		return 0, errors.New("Отсутствует: Minecraft токен")
	}
	if err := c.request(ctx, "GET", c.minecraft+"/entitlements/mcstore", token, "", nil, &reply); err != nil {
		return 0, err
	}
	if reply.Items == nil {
		return 0, errors.New("Некорректное значение: «ответ о правах доступа: отсутствует массив items»")
	}
	return len(reply.Items), nil
}
