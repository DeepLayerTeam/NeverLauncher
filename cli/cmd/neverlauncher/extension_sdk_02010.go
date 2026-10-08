package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const neverExtensionsSDKVersion02010 = neverExtensionsSDKVersion0210

func handleExtensionSDK02010(command string, args []string) error {
	switch command {
	case "init":
		return extensionInit02010(args)
	case "build":
		return extensionBuildCommand02010(args)
	case "test":
		return extensionTest02010(args)
	case "dev":
		return extensionDev02010(args)
	default:
		return fmt.Errorf("неизвестный NeverExtensions SDK команда %q", command)
	}
}

func extensionTargets02010(args []string) ([]string, error) {
	raw := strings.TrimSpace(flagValue(args, "--target", "backend"))
	if raw == "all" {
		raw = "backend,admin,desktop,cli"
	}
	seen := map[string]bool{}
	var out []string
	for _, value := range strings.Split(raw, ",") {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if !containsString([]string{"backend", "admin", "desktop", "cli"}, value) {
			return nil, fmt.Errorf("--цель содержит неподдерживаемый цель %q", value)
		}
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("в least один цель является обязательный")
	}
	sort.Strings(out)
	return out, nil
}

func extensionInit02010(args []string) error {
	targets, err := extensionTargets02010(args)
	if err != nil {
		return err
	}
	out := filepath.Clean(flagValue(args, "--out", "neverlauncher-extension"))
	id := strings.ToLower(strings.TrimSpace(flagValue(args, "--id", "ru.example.neverlauncher.extension")))
	name := strings.TrimSpace(flagValue(args, "--name", "NeverLauncher extension"))
	publisher := strings.TrimSpace(flagValue(args, "--publisher", "Example Publisher"))
	if st, err := os.Stat(out); err == nil && st.IsDir() {
		entries, _ := os.ReadDir(out)
		if len(entries) > 0 && !flagBool(args, "--force", false) {
			return fmt.Errorf("вывод каталог %s является не пустой; использовать --force", out)
		}
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	manifest := CanonicalExtensionManifest0201{SchemaVersion: "2.0", ID: id, Name: name, Version: "0.1.0", Publisher: publisher, API: neverExtensionsAPIVersion0210}
	permissions := map[string]bool{}
	for _, target := range targets {
		manifest.Targets = append(manifest.Targets, CanonicalExtensionTarget0201{Kind: target, Entrypoint: sdkEntrypoint(target)})
		switch target {
		case "backend":
			permissions["telemetry:write"] = true
		case "admin":
			permissions["ui:contribute"] = true
			permissions["project:read"] = true
			manifest.Admin = &CanonicalExtensionAdminContributions0208{Pages: []CanonicalExtensionAdminPage0208{{ID: "main", Title: name}}, Navigation: []CanonicalExtensionAdminNavigation0208{{ID: "main-nav", Label: name, PageID: "main"}}, DashboardWidgets: []CanonicalExtensionAdminWidget0208{{ID: "summary", Title: name, PageID: "main", Height: 280}}}
		case "desktop":
			permissions["desktop:contribute"] = true
			permissions["project:read"] = true
			manifest.Desktop = &CanonicalExtensionDesktopContributions0209{Pages: []CanonicalExtensionDesktopPage0209{{ID: "main", Title: name}}, Navigation: []CanonicalExtensionDesktopNavigation0209{{ID: "main-nav", Label: name, PageID: "main"}}}
		case "cli":
			permissions["cli:contribute"] = true
			manifest.CLI = &CanonicalExtensionCLIContributions0209{Namespace: "example", Commands: []CanonicalExtensionCLICommand0209{{Name: "status", Description: "Show extension status", Usage: "nl x example status"}}}
		}
	}
	for permission := range permissions {
		manifest.Permissions = append(manifest.Permissions, permission)
	}
	manifest, _, err = normalizeCanonicalExtension0201(manifest)
	if err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(out, canonicalExtensionManifestName0201), manifest); err != nil {
		return err
	}
	if err := writeExtensionScaffold02010(out, targets, id, name); err != nil {
		return err
	}
	printJSON(map[string]any{"created": true, "path": out, "id": id, "targets": targets, "sdkVersion": neverExtensionsSDKVersion02010})
	return nil
}

func writeExtensionScaffold02010(root string, targets []string, id, name string) error {
	for _, target := range targets {
		switch target {
		case "backend":
			dir := filepath.Join(root, "backend")
			if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/neverlauncher-extension/backend\n\ngo 1.22\n\nrequire gitflic.ru/skif4er/neverlauncher/sdk/backend/go v0.21.0\n"), 0o644); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(backendTemplate02010(id)), 0o644); err != nil {
				return err
			}
		case "cli":
			dir := filepath.Join(root, "cli")
			if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/neverlauncher-extension/cli\n\ngo 1.22\n\nrequire gitflic.ru/skif4er/neverlauncher/sdk/cli/go v0.21.0\n"), 0o644); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(cliTemplate02010()), 0o644); err != nil {
				return err
			}
		case "admin":
			dir := filepath.Join(root, "admin")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(uiTemplate02010("admin", name)), 0o644); err != nil {
				return err
			}
		case "desktop":
			dir := filepath.Join(root, "desktop")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(uiTemplate02010("desktop", name)), 0o644); err != nil {
				return err
			}
		}
	}
	readme := "# " + name + "\n\nGenerated by NeverLauncher 0.21.0.\n\n- `nl extension build .` builds executable targets.\n- `nl extension test .` validates/builds/tests/packages the extension.\n- `nl extension dev . --target backend` runs against the local authenticated Host Protocol.\n"
	return os.WriteFile(filepath.Join(root, "README.md"), []byte(readme), 0o644)
}

func backendTemplate02010(id string) string {
	return `package main

// SDK аутентифицировать с NEVERLAUNCHER_EXTENSION_HOST_URL и NEVERLAUNCHER_EXTENSION_HOST_TOKEN.
// Это выполняет POST /v1/hello до запуск сигнал состояния и возможность трафик.

import (
  "context"
  "os/signal"
  "syscall"
  "time"

  neverextensions "gitflic.ru/skif4er/neverlauncher/sdk/backend/go"
)

func main() {
  ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
  defer stop()
  client, err := neverextensions.NewFromEnvironment()
  if err != nil { panic(err) }
  callback, err := client.StartCallbackServer(nil, nil)
  if err != nil { panic(err) }
  defer callback.Close(context.Background())
  if _, err = client.Hello(ctx, callback.URL); err != nil { panic(err) }
  _ = client.Log(ctx, "info", "extension started", map[string]any{"sdk":"0.21.0"})
  go func(){ _ = client.HeartbeatLoop(ctx) }()
  ticker := time.NewTicker(30*time.Second); defer ticker.Stop()
  for { select { case <-ctx.Done(): return; case <-ticker.C: _, _ = client.Health(ctx) } }
}
`
}

func cliTemplate02010() string {
	return `package main

// SDK аутентифицировать с NEVERLAUNCHER_EXTENSION_HOST_URL и NEVERLAUNCHER_EXTENSION_HOST_TOKEN.
// Это выполняет POST /v1/hello до dispatching объявлять состояние команда.

import (
  "context"
  "fmt"
  neverextensions "gitflic.ru/skif4er/neverlauncher/sdk/cli/go"
)

func main() {
  neverextensions.Main(neverextensions.NewApp(
    neverextensions.Command{Name:"status", Run: func(ctx context.Context, client *neverextensions.Client, args []string) error {
      var result map[string]any
      if err := client.Capability(ctx, "extension.self", nil, &result); err != nil { return err }
      fmt.Printf("%s %v\n", client.Environment().ExtensionId, result["version"])
      return nil
    }},
  ))
}
`
}

func uiTemplate02010(kind, name string) string {
	protocol := "neverextensions." + kind + "-rpc.v1"
	extra := ""
	if kind == "desktop" {
		extra = `<button id="platform">Platform</button><script>document.getElementById('platform').onclick=()=>rpc('tauri.platform',{}).then(v=>document.getElementById('out').textContent=JSON.stringify(v,null,2)).catch(e=>document.getElementById('out').textContent=String(e));</script>`
	}
	return fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>%s</title><style>body{font:14px system-ui;margin:0;padding:16px}button{margin:0 0 12px}pre{white-space:pre-wrap}</style></head><body><h2>%s</h2>%s<pre id="out">Waiting for NeverLauncher host…</pre><script>const P=%q;let seq=0;const pending=new Map();const out=document.getElementById('out');addEventListener('message',e=>{if(e.source!==parent||!e.data||e.data.protocol!==P)return;const m=e.data;if(m.type==='rpc.response'){const p=pending.get(m.id);if(!p)return;pending.delete(m.id);m.error?p.reject(new Error(m.error)):p.resolve(m.result)}if(m.type==='host.context')out.textContent=JSON.stringify(m.context,null,2)});function rpc(method,params){const id='rpc-'+Date.now()+'-'+(++seq);parent.postMessage({protocol:P,type:'rpc.request',id,method,params},'*');return new Promise((resolve,reject)=>{pending.set(id,{resolve,reject});setTimeout(()=>{if(pending.delete(id))reject(new Error('RPC timeout'))},10000)})}rpc('context.get',{}).then(v=>out.textContent=JSON.stringify(v,null,2)).catch(e=>out.textContent=String(e));</script></body></html>`, name, name, extra, protocol)
}

func extensionBuildCommand02010(args []string) error {
	root := "."
	if len(args) > 0 && !strings.HasPrefix(args[0], "--") {
		root = args[0]
	}
	manifest, _, _, err := loadCanonicalExtension0201(root)
	if err != nil {
		return err
	}
	targetFilter := strings.ToLower(strings.TrimSpace(flagValue(args, "--target", "")))
	sdkRoot := discoverSDKRoot02010(root, flagValue(args, "--sdk-root", ""))
	built := []string{}
	for _, target := range manifest.Targets {
		if targetFilter != "" && target.Kind != targetFilter {
			continue
		}
		if err := buildTarget02010(root, target, sdkRoot); err != nil {
			return fmt.Errorf("сборка %s: %w", target.Kind, err)
		}
		built = append(built, target.Kind)
	}
	if len(built) == 0 {
		return errors.New("нет соответствовать расширение цель к сборка")
	}
	printJSON(map[string]any{"built": true, "extensionId": manifest.ID, "version": manifest.Version, "targets": built, "sdkRoot": sdkRoot})
	return nil
}

func buildTarget02010(root string, target CanonicalExtensionTarget0201, sdkRoot string) error {
	switch target.Kind {
	case "backend", "cli":
		dir := filepath.Join(root, target.Kind)
		goMod := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goMod); err != nil {
			return fmt.Errorf("%s исходник Go.mod: %w", target.Kind, err)
		}
		out := filepath.Join(root, filepath.FromSlash(target.Entrypoint))
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		return runGo02010(dir, sdkRoot, target.Kind, "build", "-trimpath", "-o", mustAbs02010(out), ".")
	case "admin", "desktop":
		packageJSON := filepath.Join(root, target.Kind, "package.json")
		if _, err := os.Stat(packageJSON); err == nil {
			cmd := exec.Command("npm", "run", "build")
			cmd.Dir = filepath.Join(root, target.Kind)
			cmd.Stdout = os.Stderr
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return err
			}
		}
		entry := filepath.Join(root, filepath.FromSlash(target.Entrypoint))
		if st, err := os.Stat(entry); err != nil || !st.Mode().IsRegular() {
			return fmt.Errorf("built entrypoint %s отсутствующий", target.Entrypoint)
		}
		return nil
	default:
		return fmt.Errorf("неподдерживаемый цель %s", target.Kind)
	}
}

func runGo02010(dir, sdkRoot, target string, args ...string) error {
	modfile := ""
	if sdkRoot != "" {
		data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err != nil {
			return err
		}
		modfile = filepath.Join(dir, ".neverlauncher-sdk.mod")
		modulePath := "gitflic.ru/skif4er/neverlauncher/sdk/" + target + "/go"
		replaceDir := filepath.Join(sdkRoot, target, "go")
		data = append(data, []byte("\nreplace "+modulePath+" => "+filepath.ToSlash(mustAbs02010(replaceDir))+"\n")...)
		if err := os.WriteFile(modfile, data, 0o600); err != nil {
			return err
		}
		defer os.Remove(modfile)
		defer os.Remove(strings.TrimSuffix(modfile, ".mod") + ".sum")
		if len(args) == 0 {
			return errors.New("Go команда отсутствующий")
		}
		args = append([]string{args[0], "-modfile=" + filepath.Base(modfile)}, args[1:]...)
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "GOWORK=off")
	return cmd.Run()
}
func mustAbs02010(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}
func discoverSDKRoot02010(root, explicit string) string {
	if v := strings.TrimSpace(explicit); v != "" {
		return mustAbs02010(v)
	}
	if v := strings.TrimSpace(os.Getenv("NEVERLAUNCHER_SDK_ROOT")); v != "" {
		return mustAbs02010(v)
	}
	p := mustAbs02010(root)
	for {
		candidate := filepath.Join(p, "sdk")
		if st, err := os.Stat(filepath.Join(candidate, "backend", "go", "go.mod")); err == nil && st.Mode().IsRegular() {
			return candidate
		}
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
	}
	return ""
}

func extensionTest02010(args []string) error {
	root := "."
	if len(args) > 0 && !strings.HasPrefix(args[0], "--") {
		root = args[0]
	}
	manifest, _, _, err := loadCanonicalExtension0201(root)
	if err != nil {
		return err
	}
	sdkRoot := discoverSDKRoot02010(root, flagValue(args, "--sdk-root", ""))
	for _, target := range manifest.Targets {
		if err := buildTarget02010(root, target, sdkRoot); err != nil {
			return err
		}
		if target.Kind == "backend" || target.Kind == "cli" {
			if err := runGo02010(filepath.Join(root, target.Kind), sdkRoot, target.Kind, "test", "./..."); err != nil {
				return fmt.Errorf("Go тест %s: %w", target.Kind, err)
			}
		}
	}
	tmp, err := os.CreateTemp("", "neverlauncher-extension-*.nlext")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	_ = os.Remove(tmpPath)
	defer os.Remove(tmpPath)
	if _, err := packExtensionPackage0202(root, tmpPath); err != nil {
		return fmt.Errorf("пакет тест: %w", err)
	}
	if _, err := verifyExtensionPackage0202(tmpPath, "", true); err != nil {
		return fmt.Errorf("пакет проверять тест: %w", err)
	}
	printJSON(map[string]any{"tested": true, "extensionId": manifest.ID, "version": manifest.Version, "targets": manifest.Targets, "packageVerified": true})
	return nil
}

// localDevHost02010 implements аутентифицировать локальная петля Хост Протокол используется через
// расширение обрабатывает. Это является намеренно отказ с блокировкой: только intrinsic возможности
// и разрешения явно пройден с --grant являются предоставлять.
type localDevHost02010 struct {
	manifest                       CanonicalExtensionManifest0201
	token, callbackToken, instance string
	grants                         map[string]bool
	fixtures                       map[string]json.RawMessage
	listener                       net.Listener
	server                         *http.Server
	hello                          chan struct{}
	once                           sync.Once
}

func newLocalDevHost02010(manifest CanonicalExtensionManifest0201, grants []string, fixturePath string) (*localDevHost02010, error) {
	token, err := randomHex02010(32)
	if err != nil {
		return nil, err
	}
	callbackToken, err := randomHex02010(32)
	if err != nil {
		return nil, err
	}
	instance, err := randomHex02010(16)
	if err != nil {
		return nil, err
	}
	h := &localDevHost02010{manifest: manifest, token: token, callbackToken: callbackToken, instance: instance, grants: map[string]bool{}, fixtures: map[string]json.RawMessage{}, hello: make(chan struct{})}
	requested := map[string]bool{}
	for _, permission := range manifest.Permissions {
		requested[strings.ToLower(strings.TrimSpace(permission))] = true
	}
	for _, g := range grants {
		g = strings.ToLower(strings.TrimSpace(g))
		if g == "" {
			continue
		}
		if !requested[g] {
			return nil, fmt.Errorf("локальный dev grant %s был не запрошенный через манифест", g)
		}
		h.grants[g] = true
	}
	if fixturePath != "" {
		data, err := os.ReadFile(fixturePath)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &h.fixtures); err != nil {
			return nil, fmt.Errorf("decode фикстура: %w", err)
		}
	}
	return h, nil
}
func randomHex02010(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func (h *localDevHost02010) start(ctx context.Context) error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	h.listener = ln
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/hello", h.helloHandler)
	mux.HandleFunc("POST /v1/heartbeat", h.authNoContent)
	mux.HandleFunc("POST /v1/log", h.logHandler)
	mux.HandleFunc("POST /v1/capabilities/{capability}", h.capabilityHandler)
	mux.HandleFunc("GET /v1/events/subscriptions", h.subscriptionsHandler)
	mux.HandleFunc("POST /v1/events/subscriptions", h.subscribeHandler)
	mux.HandleFunc("DELETE /v1/events/subscriptions/{subscriptionId}", h.authNoContent)
	h.server = &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = h.server.Shutdown(shutdownCtx)
	}()
	go h.server.Serve(ln)
	return nil
}
func (h *localDevHost02010) url() string { return "http://" + h.listener.Addr().String() }
func (h *localDevHost02010) auth(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") != "Bearer "+h.token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}
func (h *localDevHost02010) authNoContent(w http.ResponseWriter, r *http.Request) {
	if !h.auth(w, r) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (h *localDevHost02010) helloHandler(w http.ResponseWriter, r *http.Request) {
	if !h.auth(w, r) {
		return
	}
	var req map[string]any
	if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req) != nil {
		http.Error(w, "недопустимый hello", 400)
		return
	}
	helloAPI, _ := req["extensionApiVersion"].(string)
	if fmt.Sprint(req["protocolVersion"]) != neverExtensionsHostVersion0210 || !supportsHostHello0210(h.manifest.API, helloAPI) || strings.ToLower(fmt.Sprint(req["extensionId"])) != h.manifest.ID || fmt.Sprint(req["instanceId"]) != h.instance {
		http.Error(w, "хост identity/protocol несоответствие", 409)
		return
	}
	h.once.Do(func() { close(h.hello) })
	caps := h.capabilities()
	writeJSON02010(w, 200, map[string]any{"protocolVersion": neverExtensionsHostVersion0210, "extensionApiVersion": neverExtensionsAPIVersion0210, "instanceId": h.instance, "heartbeatTimeoutSeconds": 30, "capabilities": caps, "events": []string{}, "eventProtocolVersion": "1.0"})
}
func (h *localDevHost02010) logHandler(w http.ResponseWriter, r *http.Request) {
	if !h.auth(w, r) {
		return
	}
	var req struct {
		Level, Message string
		Fields         map[string]any
	}
	if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req) != nil {
		http.Error(w, "недопустимый журнал", 400)
		return
	}
	fmt.Fprintf(os.Stderr, "[extension:%s] %s %s", h.manifest.ID, strings.ToUpper(req.Level), req.Message)
	if len(req.Fields) > 0 {
		data, _ := json.Marshal(req.Fields)
		fmt.Fprintf(os.Stderr, " %s", data)
	}
	fmt.Fprintln(os.Stderr)
	w.WriteHeader(http.StatusNoContent)
}
func (h *localDevHost02010) capabilities() []string {
	out := []string{"extension.self", "host.health"}
	mapping := map[string]string{"project:read": "project.get", "release:read": "release.list", "storage:read": "storage.read", "telemetry:write": "telemetry.emit", "http:outbound": "http.fetch", "secrets:read": "secret.get"}
	for p, c := range mapping {
		if h.grants[p] {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}
func (h *localDevHost02010) capabilityHandler(w http.ResponseWriter, r *http.Request) {
	if !h.auth(w, r) {
		return
	}
	capName := strings.ToLower(strings.TrimSpace(r.PathValue("capability")))
	allowed := false
	for _, c := range h.capabilities() {
		if c == capName {
			allowed = true
			break
		}
	}
	if !allowed {
		http.Error(w, "возможность запрещён через локальный dev хост", 403)
		return
	}
	if raw, ok := h.fixtures[capName]; ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(raw)
		return
	}
	switch capName {
	case "host.health":
		writeJSON02010(w, 200, map[string]any{"status": map[string]any{"state": "dev", "healthy": true}})
	case "extension.self":
		writeJSON02010(w, 200, map[string]any{"extensionId": h.manifest.ID, "version": h.manifest.Version, "scope": "global", "generation": 1, "manifest": h.manifest})
	case "project.get":
		writeJSON02010(w, 200, map[string]any{"project": map[string]any{"id": "dev-project", "name": "Local Dev Project"}})
	case "release.list":
		writeJSON02010(w, 200, map[string]any{"items": []any{}})
	case "telemetry.emit":
		writeJSON02010(w, 200, map[string]any{"accepted": true})
	default:
		http.Error(w, "предоставлять --фикстура для этот возможность", 501)
	}
}
func (h *localDevHost02010) subscriptionsHandler(w http.ResponseWriter, r *http.Request) {
	if !h.auth(w, r) {
		return
	}
	writeJSON02010(w, 200, map[string]any{"items": []any{}})
}
func (h *localDevHost02010) subscribeHandler(w http.ResponseWriter, r *http.Request) {
	if !h.auth(w, r) {
		return
	}
	if !h.grants["events:subscribe"] {
		http.Error(w, "события:subscribe не granted", 403)
		return
	}
	writeJSON02010(w, 201, map[string]any{"id": 1, "extensionId": h.manifest.ID, "eventType": "dev.event", "mode": "async"})
}
func writeJSON02010(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func extensionDev02010(args []string) error {
	root := "."
	if len(args) > 0 && !strings.HasPrefix(args[0], "--") {
		root = args[0]
	}
	manifest, _, _, err := loadCanonicalExtension0201(root)
	if err != nil {
		return err
	}
	targetName := strings.ToLower(strings.TrimSpace(flagValue(args, "--target", "backend")))
	var target *CanonicalExtensionTarget0201
	for i := range manifest.Targets {
		if manifest.Targets[i].Kind == targetName {
			target = &manifest.Targets[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("расширение делает не объявлять цель %s", targetName)
	}
	if err := buildTarget02010(root, *target, discoverSDKRoot02010(root, flagValue(args, "--sdk-root", ""))); err != nil {
		return err
	}
	duration := time.Duration(0)
	if raw := strings.TrimSpace(flagValue(args, "--duration", "")); raw != "" {
		duration, err = time.ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("--duration: %w", err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, duration)
		defer cancel()
	}
	if targetName == "admin" || targetName == "desktop" {
		return serveUIDev02010(ctx, root, *target, manifest)
	}
	grants := multiFlag02010(args, "--grant")
	host, err := newLocalDevHost02010(manifest, grants, flagValue(args, "--fixtures", ""))
	if err != nil {
		return err
	}
	if err := host.start(ctx); err != nil {
		return err
	}
	entry := mustAbs02010(filepath.Join(root, filepath.FromSlash(target.Entrypoint)))
	argv := []string{}
	if targetName == "cli" {
		argv = afterDoubleDash02010(args)
		if len(argv) == 0 {
			argv = []string{"status"}
		}
	}
	cmd := exec.CommandContext(ctx, entry, argv...)
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = devEnvironment02010(host.url(), host.token, host.callbackToken, host.instance, manifest, targetName)
	if err := cmd.Start(); err != nil {
		return err
	}
	select {
	case <-host.hello:
		fmt.Fprintf(os.Stderr, "NeverExtensions dev host: %s target authenticated (%s)\n", targetName, host.url())
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		return errors.New("расширение сделал не аутентифицировать к локальный Хост Протокол в пределах 10s")
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		return ctx.Err()
	}
	err = cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return err
}
func devEnvironment02010(url, token, callbackToken, instance string, m CanonicalExtensionManifest0201, target string) []string {
	safe := map[string]bool{"PATH": true, "HOME": true, "USERPROFILE": true, "SYSTEMROOT": true, "WINDIR": true, "TMP": true, "TEMP": true, "TMPDIR": true, "LANG": true, "LC_ALL": true, "TZ": true}
	env := []string{}
	for _, raw := range os.Environ() {
		if p := strings.IndexByte(raw, '='); p > 0 && safe[strings.ToUpper(raw[:p])] {
			env = append(env, raw)
		}
	}
	extra := map[string]string{"NEVERLAUNCHER_EXTENSION_HOST_URL": url, "NEVERLAUNCHER_EXTENSION_HOST_TOKEN": token, "NEVERLAUNCHER_EXTENSION_CALLBACK_TOKEN": callbackToken, "NEVERLAUNCHER_EXTENSION_HOST_PROTOCOL": neverExtensionsHostVersion0210, "NEVERLAUNCHER_EXTENSION_API_VERSION": neverExtensionsAPIVersion0210, "NEVERLAUNCHER_EXTENSION_INSTANCE_ID": instance, "NEVERLAUNCHER_EXTENSION_ID": m.ID, "NEVERLAUNCHER_EXTENSION_VERSION": m.Version, "NEVERLAUNCHER_EXTENSION_SCOPE": "global", "NEVERLAUNCHER_EXTENSION_SCOPE_ID": "", "NEVERLAUNCHER_EXTENSION_TARGET": target}
	for k, v := range extra {
		env = append(env, k+"="+v)
	}
	sort.Strings(env)
	return env
}
func multiFlag02010(args []string, name string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		if args[i] == name && i+1 < len(args) {
			for _, v := range strings.Split(args[i+1], ",") {
				if v = strings.TrimSpace(v); v != "" {
					out = append(out, v)
				}
			}
			i++
		} else if strings.HasPrefix(args[i], name+"=") {
			for _, v := range strings.Split(strings.TrimPrefix(args[i], name+"="), ",") {
				if v = strings.TrimSpace(v); v != "" {
					out = append(out, v)
				}
			}
		}
	}
	return out
}
func afterDoubleDash02010(args []string) []string {
	for i, v := range args {
		if v == "--" {
			return append([]string(nil), args[i+1:]...)
		}
	}
	return nil
}

func serveUIDev02010(ctx context.Context, root string, target CanonicalExtensionTarget0201, manifest CanonicalExtensionManifest0201) error {
	entry := filepath.Join(root, filepath.FromSlash(target.Entrypoint))
	data, err := os.ReadFile(entry)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	protocol := "neverextensions." + target.Kind + "-rpc.v1"
	mux := http.NewServeMux()
	mux.HandleFunc("GET /extension", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; object-src 'none'; frame-src 'none'; form-action 'none'")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!doctype html><html><body><iframe id="ext" sandbox="allow-scripts" src="/extension" style="width:100%%;height:90vh;border:0"></iframe><script>const P=%q,F=document.getElementById('ext');F.onload=()=>F.contentWindow.postMessage({protocol:P,type:'host.context',context:{extensionId:%q,version:%q,scope:'global',scopeId:'',pageId:'main',actionId:'',bridgeAllowed:false}},'*');addEventListener('message',e=>{if(e.source!==F.contentWindow||!e.data||e.data.protocol!==P||e.data.type!=='rpc.request')return;let result={};switch(e.data.method){case'context.get':result={extensionId:%q,version:%q,scope:'global',scopeId:'',pageId:'main',actionId:'',bridgeAllowed:false};break;case'projects.list':result=[{id:'dev-project',name:'Local Dev Project'}];break;case'releases.list':result=[];break;case'tauri.platform':result={os:%q,arch:%q};break;default:F.contentWindow.postMessage({protocol:P,type:'rpc.response',id:e.data.id,error:'method not available in local dev host'},'*');return}F.contentWindow.postMessage({protocol:P,type:'rpc.response',id:e.data.id,result},'*')});</script></body></html>`, protocol, manifest.ID, manifest.Version, manifest.ID, manifest.Version, runtime.GOOS, runtime.GOARCH)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Fprintf(os.Stderr, "NeverExtensions %s dev host: http://%s/\n", target.Kind, ln.Addr())
	err = server.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
