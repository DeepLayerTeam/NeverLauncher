package neverextensions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type Client struct {
	env   HostEnvironment
	http  *http.Client
	hello HelloResponse
}

type ExitError struct {
	Code    int
	Message string
}

func (e *ExitError) Error() string { return e.Message }

func Environment() (HostEnvironment, error) {
	env := HostEnvironment{ExtensionId: strings.TrimSpace(os.Getenv("NEVERLAUNCHER_EXTENSION_ID")), ExtensionApiVersion: strings.TrimSpace(os.Getenv("NEVERLAUNCHER_EXTENSION_API_VERSION")), Version: strings.TrimSpace(os.Getenv("NEVERLAUNCHER_EXTENSION_VERSION")), Scope: strings.TrimSpace(os.Getenv("NEVERLAUNCHER_EXTENSION_SCOPE")), ScopeId: strings.TrimSpace(os.Getenv("NEVERLAUNCHER_EXTENSION_SCOPE_ID")), Target: strings.TrimSpace(os.Getenv("NEVERLAUNCHER_EXTENSION_TARGET")), HostUrl: strings.TrimRight(strings.TrimSpace(os.Getenv("NEVERLAUNCHER_EXTENSION_HOST_URL")), "/"), HostToken: strings.TrimSpace(os.Getenv("NEVERLAUNCHER_EXTENSION_HOST_TOKEN")), CallbackToken: strings.TrimSpace(os.Getenv("NEVERLAUNCHER_EXTENSION_CALLBACK_TOKEN")), InstanceId: strings.TrimSpace(os.Getenv("NEVERLAUNCHER_EXTENSION_INSTANCE_ID"))}
	if env.HostUrl == "" || env.HostToken == "" || env.ExtensionId == "" || env.InstanceId == "" || env.ExtensionApiVersion == "" {
		return HostEnvironment{}, errors.New("NeverLauncher Extension Host environment is incomplete")
	}
	if env.Scope == "" {
		env.Scope = "global"
	}
	return env, nil
}
func NewFromEnvironment() (*Client, error) {
	env, err := Environment()
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, MaxIdleConns: 4, IdleConnTimeout: 15 * time.Second}
	return &Client{env: env, http: &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) Environment() HostEnvironment { return c.env }
func (c *Client) call(ctx context.Context, path string, input, output any) error {
	buf := bytes.NewBuffer(nil)
	if input != nil {
		if err := json.NewEncoder(buf).Encode(input); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.env.HostUrl+path, buf)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.env.HostToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("NeverLauncher Host %s: HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if output != nil && len(bytes.TrimSpace(data)) > 0 {
		return json.Unmarshal(data, output)
	}
	return nil
}
func (c *Client) Hello(ctx context.Context) (HelloResponse, error) {
	var out HelloResponse
	err := c.call(ctx, "/v1/hello", HelloRequest{ProtocolVersion: HostProtocolVersion, ExtensionApiVersion: ExtensionAPIVersion, InstanceId: c.env.InstanceId, ExtensionId: c.env.ExtensionId, Pid: os.Getpid()}, &out)
	if err != nil {
		return HelloResponse{}, err
	}
	if out.ProtocolVersion != HostProtocolVersion || out.ExtensionApiVersion != ExtensionAPIVersion || out.InstanceId != c.env.InstanceId {
		return HelloResponse{}, errors.New("NeverLauncher Host hello identity/protocol mismatch")
	}
	c.hello = out
	return out, nil
}
func (c *Client) Log(ctx context.Context, level, message string, fields map[string]any) error {
	return c.call(ctx, "/v1/log", LogRequest{Level: level, Message: message, Fields: fields}, nil)
}
func (c *Client) Capability(ctx context.Context, name string, request, response any) error {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || strings.Contains(name, "/") {
		return errors.New("invalid capability name")
	}
	return c.call(ctx, "/v1/capabilities/"+name, request, response)
}

type Command struct {
	Name string
	Run  func(context.Context, *Client, []string) error
}
type App struct{ Commands map[string]Command }

func NewApp(commands ...Command) *App {
	m := map[string]Command{}
	for _, cmd := range commands {
		if strings.TrimSpace(cmd.Name) != "" && cmd.Run != nil {
			m[cmd.Name] = cmd
		}
	}
	return &App{Commands: m}
}
func (a *App) Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return &ExitError{Code: 64, Message: "command is required"}
	}
	cmd, ok := a.Commands[args[0]]
	if !ok {
		return &ExitError{Code: 64, Message: "unknown command: " + args[0]}
	}
	client, err := NewFromEnvironment()
	if err != nil {
		return &ExitError{Code: 70, Message: err.Error()}
	}
	if _, err := client.Hello(ctx); err != nil {
		return &ExitError{Code: 77, Message: err.Error()}
	}
	return cmd.Run(ctx, client, args[1:])
}
func Main(app *App) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err := app.Run(ctx, os.Args[1:]); err != nil {
		code := 70
		var exit *ExitError
		if errors.As(err, &exit) {
			code = exit.Code
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(code)
	}
}
