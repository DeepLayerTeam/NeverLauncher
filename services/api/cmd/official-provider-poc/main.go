// Команда official-provider-poc проверяет СОБСТВЕННУЮ регистрацию публичного клиента
// Microsoft Entra по ЖИВЫМ Microsoft, Xbox Live, XSTS и Minecraft Services. Она
// никогда не сохраняет учётные данные и не принимает офлайн-ответ или имитацию за
// одобрение.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/officialminecraft"
)

// Переопределяется через -ldflags -X при промышленной сборке.
var releaseVersion = "0.27.0"

type providerClient interface {
	Begin(context.Context, string) (officialminecraft.DeviceCode, error)
	Complete(context.Context, string, string) (officialminecraft.OAuthTokens, error)
	AuthorizationURL(string, string, string, string) (string, error)
	ExchangeAuthorizationCode(context.Context, string, string, string, string) (officialminecraft.OAuthTokens, error)
	Refresh(context.Context, string, string) (officialminecraft.OAuthTokens, error)
	ExchangeWithStages(context.Context, string, func(string)) (officialminecraft.MinecraftToken, error)
	EntitlementCount(context.Context, string) (int, error)
	Profile(context.Context, string) (officialminecraft.Profile, error)
	VerifyOnlineSession(context.Context, string, officialminecraft.Profile) error
}

type options struct {
	ClientID             string
	Flow                 string
	Timeout              time.Duration
	OpenBrowser          bool
	RequireOnlineSession bool
	ProbeServer          string
	ProbeProtocol        int
}

type stage struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	ErrorCode  string `json:"errorCode,omitempty"`
	HTTPStatus int    `json:"httpStatus,omitempty"`
}

type report struct {
	Schema                  string  `json:"schema"`
	Version                 string  `json:"version"`
	TimestampUTC            string  `json:"timestampUTC"`
	ClientID                string  `json:"clientId"`
	OAuthFlow               string  `json:"oauthFlow"`
	Provider                string  `json:"provider"`
	Stages                  []stage `json:"stages"`
	Result                  string  `json:"result"`
	MinecraftServicesAccess string  `json:"minecraftServicesAccess"`
	ExternalAppApproval     string  `json:"externalAppApproval"`
	MinecraftProfileSHA256  string  `json:"minecraftProfileSHA256,omitempty"`
	EntitlementItems        *int    `json:"entitlementItems,omitempty"`
	OS                      string  `json:"os"`
	Architecture            string  `json:"architecture"`
	OnlineModeSession       string  `json:"onlineModeSession"`
	ServerHandshake         string  `json:"serverHandshake"`
}

func newReport(opt options) *report {
	return &report{Schema: "launcher.official-provider-poc.v1", Version: releaseVersion, TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), ClientID: opt.ClientID, OAuthFlow: opt.Flow, Provider: "fixed_official_microsoft_xbox_minecraft_hosts", Stages: []stage{}, Result: "blocked", MinecraftServicesAccess: "not_verified", ExternalAppApproval: "requires_independent_provider_confirmation", OS: runtime.GOOS, Architecture: runtime.GOARCH, OnlineModeSession: "not_verified", ServerHandshake: "not_tested"}
}

func (r *report) pass(name string) { r.Stages = append(r.Stages, stage{Name: name, Status: "passed"}) }
func classify(err error) (string, int) {
	if err == nil {
		return "", 0
	}
	var s *officialminecraft.ServiceError
	if errors.As(err, &s) {
		switch s.Code {
		case "invalid_app_registration":
			return "minecraft_app_not_authorized", s.Status
		case "xsts_2148916233":
			return "xbox_profile_missing", s.Status
		case "xsts_2148916235":
			return "xbox_region_restricted", s.Status
		case "xsts_2148916238":
			return "xbox_family_restricted", s.Status
		}
		if s.Status == http.StatusForbidden {
			return "provider_forbidden", s.Status
		}
		if s.Status == http.StatusTooManyRequests {
			return "provider_rate_limited", s.Status
		}
		if s.Status == http.StatusUnauthorized {
			return "provider_unauthorized", s.Status
		}
		if s.Status >= 500 {
			return "provider_unavailable", s.Status
		}
		return "provider_request_rejected", s.Status
	}
	switch {
	case errors.Is(err, officialminecraft.ErrDenied):
		return "user_denied", 0
	case errors.Is(err, officialminecraft.ErrExpired):
		return "authorization_expired", 0
	case errors.Is(err, officialminecraft.ErrOnlineIdentityMismatch):
		return "online_mode_identity_mismatch", 0
	case errors.Is(err, officialminecraft.ErrOnlineSessionRejected):
		return "online_mode_session_rejected", 0
	case errors.Is(err, officialminecraft.ErrUnlicensed):
		return "minecraft_java_profile_missing", 0
	case errors.Is(err, context.Canceled):
		return "cancelled", 0
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout", 0
	default:
		return "verification_error", 0
	}
}
func (r *report) fail(name string, err error) {
	code, status := classify(err)
	r.Stages = append(r.Stages, stage{Name: name, Status: "blocked", ErrorCode: code, HTTPStatus: status})
}

func randomBase64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type callbackResult struct {
	Code string
	Err  error
}

// browserGrant привязывается только к IPv4 loopback, проверяет Host, state, путь
// обратного вызова и длину кода. HTTP-сервер не пишет учётные данные в журналы и не
// перенаправляет на удалённый URL.
func browserGrant(ctx context.Context, c providerClient, opt options, output io.Writer) (officialminecraft.OAuthTokens, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return officialminecraft.OAuthTokens{}, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirect := fmt.Sprintf("http://localhost:%d/minecraft-poc/callback", port)
	state, err := randomBase64(32)
	if err != nil {
		listener.Close()
		return officialminecraft.OAuthTokens{}, err
	}
	verifier, err := randomBase64(64)
	if err != nil {
		listener.Close()
		return officialminecraft.OAuthTokens{}, err
	}
	challenge, err := officialminecraft.PKCEChallenge(verifier)
	if err != nil {
		listener.Close()
		return officialminecraft.OAuthTokens{}, err
	}
	authURL, err := c.AuthorizationURL(opt.ClientID, redirect, state, challenge)
	if err != nil {
		listener.Close()
		return officialminecraft.OAuthTokens{}, err
	}
	result := make(chan callbackResult, 1)
	mux := http.NewServeMux()
	expectedHost := fmt.Sprintf("localhost:%d", port)
	mux.HandleFunc("/minecraft-poc/callback", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.Method != "GET" || r.Host != expectedHost {
			http.Error(w, "Invalid callback", http.StatusBadRequest)
			return
		}
		params := r.URL.Query()
		if len(r.URL.RawQuery) > 8192 || len(params["state"]) != 1 ||
			(len(params["code"]) != 1 && len(params["error"]) != 1) ||
			(len(params["code"]) > 0 && len(params["error"]) > 0) ||
			len(params["code"]) > 1 || len(params["error"]) > 1 {
			http.Error(w, "Invalid callback", http.StatusBadRequest)
			return
		}
		got := params.Get("state")
		if subtle.ConstantTimeCompare([]byte(got), []byte(state)) != 1 {
			http.Error(w, "Invalid state", http.StatusBadRequest)
			return
		}
		var cb callbackResult
		if r.URL.Query().Get("error") != "" {
			cb.Err = officialminecraft.ErrDenied
		} else {
			cb.Code = r.URL.Query().Get("code")
			if cb.Code == "" || len(cb.Code) > 4096 || strings.ContainsAny(cb.Code, "\r\n") {
				cb.Err = errors.New("invalid authorization callback")
			}
		}
		select {
		case result <- cb:
			if cb.Err != nil {
				fmt.Fprint(w, "Sign-in declined. Return to the terminal.\n")
			} else {
				fmt.Fprint(w, "Authorization received. Return to the terminal.\n")
			}
		default:
			http.Error(w, "Already handled", http.StatusConflict)
		}
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 8 << 10}
	go func() { _ = server.Serve(listener) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	fmt.Fprintln(output, "Microsoft personal-account login URL (open in your system browser):")
	fmt.Fprintln(output, authURL)
	fmt.Fprintln(output, "Redirect registration: http://localhost/minecraft-poc/callback (native/public client; loopback port is dynamic).")
	if opt.OpenBrowser {
		if err := openBrowser(authURL); err != nil {
			fmt.Fprintln(output, "Could not open browser automatically; use the URL above.")
		}
	}
	select {
	case <-ctx.Done():
		return officialminecraft.OAuthTokens{}, ctx.Err()
	case res := <-result:
		if res.Err != nil {
			return officialminecraft.OAuthTokens{}, res.Err
		}
		return c.ExchangeAuthorizationCode(ctx, opt.ClientID, redirect, res.Code, verifier)
	}
}

func openBrowser(addr string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", addr)
	case "darwin":
		cmd = exec.Command("open", addr)
	case "linux":
		cmd = exec.Command("xdg-open", addr)
	default:
		return errors.New("Не найден поддерживаемый механизм запуска браузера")
	}
	return cmd.Run()
}

func deviceGrant(ctx context.Context, c providerClient, opt options, output io.Writer) (officialminecraft.OAuthTokens, error) {
	code, err := c.Begin(ctx, opt.ClientID)
	if err != nil {
		return officialminecraft.OAuthTokens{}, err
	}
	fmt.Fprintln(output, "Microsoft device verification URL:", code.VerificationURI)
	fmt.Fprintln(output, "Enter this one-time user code:", code.UserCode)
	fmt.Fprintln(output, "Never enter your Microsoft password into Launcher.")
	expiry := time.NewTimer(time.Duration(code.ExpiresIn) * time.Second)
	defer expiry.Stop()
	interval := time.Duration(code.Interval) * time.Second
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	for {
		delay := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			delay.Stop()
			return officialminecraft.OAuthTokens{}, ctx.Err()
		case <-expiry.C:
			delay.Stop()
			return officialminecraft.OAuthTokens{}, officialminecraft.ErrExpired
		case <-delay.C:
		}
		tokens, err := c.Complete(ctx, opt.ClientID, code.DeviceCode)
		if err == nil {
			return tokens, nil
		}
		if errors.Is(err, officialminecraft.ErrPending) {
			continue
		}
		if errors.Is(err, officialminecraft.ErrSlowDown) {
			interval += 5 * time.Second
			continue
		}
		return officialminecraft.OAuthTokens{}, err
	}
}

func verify(ctx context.Context, c providerClient, opt options, output io.Writer) *report {
	r := newReport(opt)
	if err := officialminecraft.ValidateClientID(opt.ClientID); err != nil {
		r.fail("app_registration", err)
		return r
	}
	if opt.Flow != "browser" && opt.Flow != "device" {
		r.fail("oauth_flow", errors.New("invalid flow"))
		return r
	}
	r.pass("client_id_format_valid")
	var oauth officialminecraft.OAuthTokens
	var err error
	if opt.Flow == "browser" {
		oauth, err = browserGrant(ctx, c, opt, output)
	} else {
		oauth, err = deviceGrant(ctx, c, opt, output)
	}
	if err != nil {
		r.fail("microsoft_oauth", err)
		return r
	}
	r.pass("microsoft_oauth")
	if oauth.RefreshToken == "" {
		r.fail("microsoft_refresh", errors.New("offline_access not granted"))
		return r
	}
	refreshed, err := c.Refresh(ctx, opt.ClientID, oauth.RefreshToken)
	if err != nil {
		r.fail("microsoft_refresh", err)
		return r
	}
	r.pass("microsoft_refresh")
	token, err := c.ExchangeWithStages(ctx, refreshed.AccessToken, func(name string) { r.pass(name) })
	if err != nil {
		name := "xbox_live"
		if len(r.Stages) > 0 {
			last := r.Stages[len(r.Stages)-1].Name
			switch last {
			case "xbox_live":
				name = "xsts"
			case "xsts":
				name = "minecraft_token"
			}
		}
		r.fail(name, err)
		return r
	}
	entitlements, err := c.EntitlementCount(ctx, token.AccessToken)
	if err != nil {
		r.fail("minecraft_entitlements", err)
		return r
	}
	r.EntitlementItems = &entitlements
	r.pass("minecraft_entitlements")
	profile, err := c.Profile(ctx, token.AccessToken)
	if err != nil {
		r.fail("minecraft_profile", err)
		return r
	}
	r.pass("minecraft_profile")
	digest := sha256.Sum256([]byte(strings.ToLower(profile.ID)))
	r.MinecraftProfileSHA256 = hex.EncodeToString(digest[:])
	r.MinecraftServicesAccess = "verified_live_profile"
	r.Result = "provider_access_verified"
	if opt.RequireOnlineSession {
		if err := c.VerifyOnlineSession(ctx, token.AccessToken, profile); err != nil {
			r.Result = "blocked"
			r.fail("sessionserver_join_has_joined", err)
			return r
		}
		r.pass("sessionserver_join_has_joined")
		r.OnlineModeSession = "verified_live_join_has_joined"
		r.Result = "online_session_verified"
	}
	if opt.ProbeServer != "" {
		if !opt.RequireOnlineSession {
			r.fail("server_online_mode_probe", errors.New("online sessionserver verification required before probing server"))
			r.Result = "blocked"
			return r
		}
		if err := probeOnlineMode(ctx, opt.ProbeServer, opt.ProbeProtocol); err != nil {
			r.fail("server_online_mode_probe", err)
			r.Result = "blocked"
			return r
		}
		r.pass("server_online_mode_probe")
		r.ServerHandshake = "encryption_requested_without_completing_game_login"
	}
	return r
}

func writeReport(path string, r *report) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if path == "" {
		_, err = os.Stdout.Write(b)
		return err
	}
	// Эксклюзивное создание, строгие права и запрет следования символьным ссылкам:
	// учётных данных нет, но доказательство может идентифицировать регистрацию
	// приложения пользователя.
	file, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err = file.Write(b); err != nil {
		return err
	}
	return file.Sync()
}

func main() {
	clientID := flag.String("client-id", os.Getenv("LAUNCHER_MINECRAFT_MICROSOFT_CLIENT_ID"), "UUID собственного публичного клиентского приложения Entra")
	flow := flag.String("flow", "browser", "browser (код авторизации + PKCE) или device")
	output := flag.String("report", "", "Путь к новому JSON-отчёту (создаётся эксклюзивно, права 0600); по умолчанию stdout")
	timeout := flag.Duration("timeout", 15*time.Minute, "Общий тайм-аут")
	noOpen := flag.Bool("no-open", false, "Вывести ссылку, не запуская браузер по умолчанию")
	online := flag.Bool("online-session", true, "Выполнить реальную проверку Mojang join/hasJoined; требуется для GA-сертификации официальной авторизации Minecraft")
	server := flag.String("probe-server", "", "Необязательный host:port разрешённого сервера online-mode (проверка рукопожатия, НЕ полный игровой вход)")
	protocol := flag.Int("protocol", 0, "Версия протокола Minecraft для --probe-server, например 767 для 1.21")
	flag.Parse()
	if *server != "" && (!*online || *protocol < 1 || *protocol > 1000000) {
		fmt.Fprintln(os.Stderr, "--probe-server requires --online-session=true and a positive --protocol")
		os.Exit(2)
	}
	if *timeout <= 0 || *timeout > 30*time.Minute {
		fmt.Fprintln(os.Stderr, "--timeout must be within (0, 30m]")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	r := verify(ctx, officialminecraft.New(), options{ClientID: *clientID, Flow: *flow, Timeout: *timeout, OpenBrowser: !*noOpen, RequireOnlineSession: *online, ProbeServer: *server, ProbeProtocol: *protocol}, os.Stderr)
	if err := writeReport(*output, r); err != nil {
		fmt.Fprintln(os.Stderr, "Could not safely save report:", err)
		os.Exit(3)
	}
	if r.Result != "provider_access_verified" && r.Result != "online_session_verified" {
		os.Exit(2)
	}
}
