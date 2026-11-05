// Пакет officialminecraft реализует публичную цепочку авторизации Microsoft/Xbox/Minecraft Java
// и операции с текстурами, принадлежащими учётной записи. Он не принимает
// локальные идентификаторы Yggdrasil как доказательство владения.
package officialminecraft

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	microsoftOrigin = "https://login.microsoftonline.com/consumers/oauth2/v2.0"
	xboxOrigin      = "https://user.auth.xboxlive.com"
	xstsOrigin      = "https://xsts.auth.xboxlive.com"
	minecraftOrigin = "https://api.minecraftservices.com"
	maxResponse     = 1 << 20
)

var ErrPending = errors.New("authorization_pending")
var ErrSlowDown = errors.New("slow_down")
var ErrExpired = errors.New("expired_token")
var ErrDenied = errors.New("access_denied")
var ErrUnlicensed = errors.New("Нет доступного Java-профиля Minecraft")

type Client struct {
	http                                            *http.Client
	microsoft, xbox, xsts, minecraft, sessionserver string
}

func New() *Client {
	return &Client{http: &http.Client{Timeout: 18 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, microsoft: microsoftOrigin, xbox: xboxOrigin, xsts: xstsOrigin, minecraft: minecraftOrigin, sessionserver: sessionServerOrigin}
}

type DeviceCode struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message,omitempty"`
}
type OAuthTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}
type MinecraftToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}
type Skin struct {
	ID      string `json:"id"`
	State   string `json:"state"`
	URL     string `json:"url"`
	Variant string `json:"variant"`
}
type Cape struct {
	ID    string `json:"id"`
	State string `json:"state"`
	URL   string `json:"url"`
	Alias string `json:"alias,omitempty"`
}
type Profile struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Skins []Skin `json:"skins"`
	Capes []Cape `json:"capes"`
}
type ServiceError struct {
	Status int
	Code   string
}

func (e *ServiceError) Error() string {
	return fmt.Sprintf("upstream Minecraft authentication service: status=%d code=%s", e.Status, e.Code)
}

func (c *Client) request(ctx context.Context, method, addr, bearer, contentType string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, addr, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	var resp *http.Response
	// Повторять разрешено только идемпотентные запросы чтения. Minecraft Services иногда
	// ограничивает частоту запросов профиля; повтор записи или обмена OAuth небезопасен.
	for attempt := 0; ; attempt++ {
		resp, err = c.http.Do(req)
		if err != nil {
			return err
		}
		if method != http.MethodGet || attempt >= 2 ||
			(resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusBadGateway && resp.StatusCode != http.StatusServiceUnavailable && resp.StatusCode != http.StatusGatewayTimeout) {
			break
		}
		// Считайте ограниченный объём ответа, чтобы соединение можно было вернуть в пул.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
		resp.Body.Close()
		delay := time.Duration(100*(1<<attempt)) * time.Millisecond
		if retry := resp.Header.Get("Retry-After"); retry != "" {
			if seconds, parseErr := strconv.Atoi(retry); parseErr == nil && seconds >= 0 && seconds <= 2 {
				delay = time.Duration(seconds) * time.Second
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return err
	}
	if len(b) > maxResponse {
		return errors.New("Ответ официального сервиса Minecraft превышает допустимый размер")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var body struct {
			Error        string `json:"error"`
			ErrorMessage string `json:"errorMessage"`
			XErr         int64  `json:"XErr"`
		}
		_ = json.Unmarshal(b, &body)
		code := body.Error
		// Minecraft Services может отклонить корректную цепочку OAuth/XSTS,
		// если идентификатор клиентского приложения не был разрешён.
		// Нормализуйте сообщение провайдера; не выводите произвольный текст его ответа.
		if resp.StatusCode == http.StatusForbidden && strings.Contains(strings.ToLower(body.ErrorMessage), "Недопустимая регистрация приложения") {
			code = "invalid_app_registration"
		}
		if code == "" && body.XErr != 0 {
			code = fmt.Sprintf("xsts_%d", body.XErr)
		}
		if code == "" {
			code = "upstream_error"
		}
		// Коды приходят из недоверенного внешнего источника; не допускайте утечки учётных данных
		// в структурированные свидетельства CLI, журналы и будущие сообщения об ошибках.
		if len(code) > 64 || !safeServiceCode(code) {
			code = "upstream_error"
		}
		switch code {
		case "authorization_pending":
			return ErrPending
		case "slow_down":
			return ErrSlowDown
		case "expired_token":
			return ErrExpired
		case "authorization_declined", "access_denied", "bad_verification_code":
			return ErrDenied
		}
		return &ServiceError{Status: resp.StatusCode, Code: code}
	}
	if out != nil {
		if len(b) == 0 {
			return errors.New("Пустой ответ официального сервиса Minecraft")
		}
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("Некорректное значение: официальный Minecraft JSON: %w", err)
		}
	}
	return nil
}
func safeServiceCode(code string) bool {
	for _, r := range code {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-' && r != '.' {
			return false
		}
	}
	return code != ""
}

func form(fields url.Values) (io.Reader, string) {
	return strings.NewReader(fields.Encode()), "application/x-www-form-urlencoded"
}
func jsonBody(v any) (io.Reader, string, error) {
	b, err := json.Marshal(v)
	return bytes.NewReader(b), "application/json", err
}
func (c *Client) Begin(ctx context.Context, clientID string) (DeviceCode, error) {
	var code DeviceCode
	body, contentType := form(url.Values{"client_id": {clientID}, "scope": {"XboxLive.signin offline_access"}})
	err := c.request(ctx, "POST", c.microsoft+"/devicecode", "", contentType, body, &code)
	if err != nil {
		return code, err
	}
	if code.DeviceCode == "" || code.UserCode == "" || code.ExpiresIn <= 0 || code.ExpiresIn > 1800 || code.VerificationURI == "" {
		return DeviceCode{}, errors.New("Неполный ответ Microsoft с кодом устройства")
	}
	if code.Interval < 5 {
		code.Interval = 5
	}
	u, err := url.Parse(code.VerificationURI)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" || (u.Hostname() != "microsoft.com" && !strings.HasSuffix(u.Hostname(), ".microsoft.com") && u.Hostname() != "microsoftonline.com" && !strings.HasSuffix(u.Hostname(), ".microsoftonline.com")) {
		return DeviceCode{}, errors.New("Недоверенный URI проверки Microsoft")
	}
	return code, nil
}
func (c *Client) Complete(ctx context.Context, clientID, deviceCode string) (OAuthTokens, error) {
	var tokens OAuthTokens
	body, contentType := form(url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "client_id": {clientID}, "device_code": {deviceCode}})
	err := c.request(ctx, "POST", c.microsoft+"/token", "", contentType, body, &tokens)
	if err != nil {
		return tokens, err
	}
	if tokens.AccessToken == "" || tokens.TokenType != "Bearer" {
		return OAuthTokens{}, errors.New("Неполные данные: Microsoft токены")
	}
	return tokens, nil
}
func (c *Client) Refresh(ctx context.Context, clientID, refresh string) (OAuthTokens, error) {
	var tokens OAuthTokens
	body, contentType := form(url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refresh}, "scope": {"XboxLive.signin offline_access"}})
	err := c.request(ctx, "POST", c.microsoft+"/token", "", contentType, body, &tokens)
	if err != nil {
		return tokens, err
	}
	if tokens.AccessToken == "" || tokens.TokenType != "Bearer" {
		return OAuthTokens{}, errors.New("Некорректное значение: «Microsoft refresh response»")
	}
	if tokens.RefreshToken == "" {
		tokens.RefreshToken = refresh
	}
	return tokens, nil
}
func (c *Client) Exchange(ctx context.Context, microsoftToken string) (MinecraftToken, error) {
	return c.ExchangeWithStages(ctx, microsoftToken, nil)
}

// ExchangeWithStages выдаёт только названия успешно пройденных этапов провайдера,
// но не учётные данные. Это позволяет установить, на каком этапе реальная проверка
// завершилась ошибкой, не записывая токены доступа в файлы свидетельств.
func (c *Client) ExchangeWithStages(ctx context.Context, microsoftToken string, stagePassed func(string)) (MinecraftToken, error) {
	if microsoftToken == "" {
		return MinecraftToken{}, errors.New("Отсутствует: Microsoft токен доступа")
	}
	var xbl struct {
		Token         string `json:"Token"`
		DisplayClaims struct {
			XUI []struct {
				UHS string `json:"uhs"`
			} `json:"xui"`
		} `json:"DisplayClaims"`
	}
	body, ct, err := jsonBody(map[string]any{"Properties": map[string]any{"AuthMethod": "RPS", "SiteName": "user.auth.xboxlive.com", "RpsTicket": "d=" + microsoftToken}, "RelyingParty": "http://auth.xboxlive.com", "TokenType": "JWT"})
	if err != nil {
		return MinecraftToken{}, err
	}
	if err = c.request(ctx, "POST", c.xbox+"/user/authenticate", "", ct, body, &xbl); err != nil {
		return MinecraftToken{}, err
	}
	if xbl.Token == "" || len(xbl.DisplayClaims.XUI) != 1 || xbl.DisplayClaims.XUI[0].UHS == "" {
		return MinecraftToken{}, errors.New("Некорректное значение: «Xbox Live response»")
	}
	if stagePassed != nil {
		stagePassed("xbox_live")
	}
	var xsts struct {
		Token         string `json:"Token"`
		DisplayClaims struct {
			XUI []struct {
				UHS string `json:"uhs"`
			} `json:"xui"`
		} `json:"DisplayClaims"`
	}
	body, ct, err = jsonBody(map[string]any{"Properties": map[string]any{"SandboxId": "RETAIL", "UserTokens": []string{xbl.Token}}, "RelyingParty": "rp://api.minecraftservices.com/", "TokenType": "JWT"})
	if err != nil {
		return MinecraftToken{}, err
	}
	if err = c.request(ctx, "POST", c.xsts+"/xsts/authorize", "", ct, body, &xsts); err != nil {
		return MinecraftToken{}, err
	}
	if xsts.Token == "" || len(xsts.DisplayClaims.XUI) != 1 || xsts.DisplayClaims.XUI[0].UHS != xbl.DisplayClaims.XUI[0].UHS {
		return MinecraftToken{}, errors.New("Несовпадение: «Xbox identity»")
	}
	if stagePassed != nil {
		stagePassed("xsts")
	}
	body, ct, err = jsonBody(map[string]string{"identityToken": "XBL3.0 x=" + xsts.DisplayClaims.XUI[0].UHS + ";" + xsts.Token})
	if err != nil {
		return MinecraftToken{}, err
	}
	var result MinecraftToken
	if err = c.request(ctx, "POST", c.minecraft+"/authentication/login_with_xbox", "", ct, body, &result); err != nil {
		return MinecraftToken{}, err
	}
	if result.AccessToken == "" || result.TokenType != "Bearer" || result.ExpiresIn <= 0 {
		return MinecraftToken{}, errors.New("Некорректное значение: Minecraft токен доступа")
	}
	if stagePassed != nil {
		stagePassed("minecraft_token")
	}
	return result, nil
}
func (c *Client) Profile(ctx context.Context, token string) (Profile, error) {
	var p Profile
	err := c.request(ctx, "GET", c.minecraft+"/minecraft/profile", token, "", nil, &p)
	if err != nil {
		return p, err
	}
	if !validOfficialSubject(p.ID, p.Name) {
		return Profile{}, ErrUnlicensed
	}
	return p, nil
}
func (c *Client) Entitled(ctx context.Context, token string) error {
	// Конечная точка профиля авторитетна и для Game Pass, и для платной лицензии Java.
	// Для Game Pass список прав может законно быть пустым. Отсутствующий профиль
	// отклоняется через Profile: наличие аккаунта Xbox не доказывает владение Java.
	_, err := c.Profile(ctx, token)
	return err
}
func (c *Client) UploadSkin(ctx context.Context, token, variant string, png []byte) (Profile, error) {
	if variant != "classic" && variant != "slim" {
		return Profile{}, errors.New("Некорректное значение: «Minecraft skin variant»")
	}
	if len(png) == 0 || len(png) > 4<<20 {
		return Profile{}, errors.New("Некорректное значение: «Minecraft skin payload»")
	}
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	if err := mw.WriteField("variant", variant); err != nil {
		return Profile{}, err
	}
	part, err := mw.CreateFormFile("file", "skin.png")
	if err != nil {
		return Profile{}, err
	}
	if _, err = part.Write(png); err != nil {
		return Profile{}, err
	}
	if err = mw.Close(); err != nil {
		return Profile{}, err
	}
	var p Profile
	err = c.request(ctx, "POST", c.minecraft+"/minecraft/profile/skins", token, mw.FormDataContentType(), &b, &p)
	return p, err
}
func (c *Client) ResetSkin(ctx context.Context, token string) error {
	return c.request(ctx, "DELETE", c.minecraft+"/minecraft/profile/skins/active", token, "", nil, nil)
}
func (c *Client) SelectCape(ctx context.Context, token, id string) (Profile, error) {
	p, err := c.Profile(ctx, token)
	if err != nil {
		return Profile{}, err
	}
	owned := false
	for _, cape := range p.Capes {
		if cape.ID == id && id != "" {
			owned = true
			break
		}
	}
	if !owned {
		return Profile{}, errors.New("Плащ не принадлежит официальной учётной записи Minecraft")
	}
	body, ct, err := jsonBody(map[string]string{"capeId": id})
	if err != nil {
		return Profile{}, err
	}
	var updated Profile
	err = c.request(ctx, "PUT", c.minecraft+"/minecraft/profile/capes/active", token, ct, body, &updated)
	return updated, err
}
func (c *Client) ResetCape(ctx context.Context, token string) error {
	return c.request(ctx, "DELETE", c.minecraft+"/minecraft/profile/capes/active", token, "", nil, nil)
}

// ConfirmTexture0395 получает *фактический* официальный профиль после успешного
// изменения текстуры. Minecraft Services может подтвердить запись раньше,
// чем обновится представление профиля; повторы ограничены и никогда не повторяют
// запись. Другой UUID — ошибка идентичности, которую нельзя исправить повтором.
// тип: skin-upload, skin-reset, cape-select, cape-reset.
func (c *Client) ConfirmTexture0395(ctx context.Context, token, uuid, kind, value string) (Profile, error) {
	if uuid == "" || token == "" {
		return Profile{}, ErrDenied
	}
	for attempt := 0; attempt < 5; attempt++ {
		profile, err := c.Profile(ctx, token)
		if err == nil {
			if !strings.EqualFold(profile.ID, uuid) {
				return Profile{}, ErrDenied
			}
			if confirmedTexture0395(profile, kind, value) {
				return profile, nil
			}
		} else if ctx.Err() != nil {
			return Profile{}, ctx.Err()
		} else {
			var upstream *ServiceError
			if errors.As(err, &upstream) && (upstream.Status == 401 || upstream.Status == 403 || upstream.Status == 404 || upstream.Status == 429) {
				return Profile{}, err
			}
			if errors.Is(err, ErrUnlicensed) {
				return Profile{}, err
			}
		}
		if attempt < 4 {
			timer := time.NewTimer(350 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return Profile{}, ctx.Err()
			case <-timer.C:
			}
		}
	}
	return Profile{}, errors.New("Minecraft Services не подтвердил обновлённое состояние текстур")
}

func confirmedTexture0395(p Profile, kind, value string) bool {
	switch kind {
	case "skin-upload":
		for _, skin := range p.Skins {
			if skin.State == "ACTIVE" && strings.EqualFold(skin.Variant, value) {
				return true
			}
		}
	case "cape-select":
		for _, cape := range p.Capes {
			if cape.State == "ACTIVE" && cape.ID == value {
				return true
			}
		}
	case "cape-reset":
		for _, cape := range p.Capes {
			if cape.State == "ACTIVE" {
				return false
			}
		}
		return true
	case "skin-reset":
		// Скин по умолчанию после сброса зависит от провайдера. Только актуальный
		// профиль, проверенный токеном (выше), считается авторитетным.
		return true
	}
	return false
}
