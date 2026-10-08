package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const extensionCLIProtocol0209 = "neverextensions.cli.v1"

type extensionCLICommand0209 struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Usage       string `json:"usage,omitempty"`
}
type extensionCLIContribution0209 struct {
	Namespace string                    `json:"namespace"`
	Commands  []extensionCLICommand0209 `json:"commands"`
}
type extensionCLICatalogItem0209 struct {
	ExtensionID string                       `json:"extensionId"`
	Name        string                       `json:"name"`
	Version     string                       `json:"version"`
	Scope       string                       `json:"scope"`
	ScopeID     string                       `json:"scopeId,omitempty"`
	CLI         extensionCLIContribution0209 `json:"cli"`
}

func fetchExtensionCLICatalog0209(backend, token string) ([]extensionCLICatalogItem0209, error) {
	payload, err := httpJSONWithAuth(http.MethodGet, backend+"/api/v1/admin/extension-cli/catalog", nil, token)
	if err != nil {
		return nil, err
	}
	data, ok := payload["data"]
	if !ok {
		return nil, errors.New("расширение CLI каталог ответ имеет нет данные")
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Protocol string                        `json:"protocol"`
		Items    []extensionCLICatalogItem0209 `json:"items"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if envelope.Protocol != extensionCLIProtocol0209 {
		return nil, fmt.Errorf("неподдерживаемый расширение CLI протокол %q", envelope.Protocol)
	}
	return envelope.Items, nil
}

func handleExtensionCLI0209(args []string) error {
	if len(args) == 0 {
		return errors.New("расширение CLI требует подкоманду: список, запуск, завершение")
	}
	command := strings.ToLower(strings.TrimSpace(args[0]))
	rest := args[1:]
	backend := adminBackendURL(rest)
	if backend == "" {
		return errors.New("расширение CLI требует --серверная часть <URL>")
	}
	token := backendToken(rest)
	if token == "" {
		return errors.New("расширение CLI требует --токен или NEVERLAUNCHER_TOKEN")
	}
	items, err := fetchExtensionCLICatalog0209(backend, token)
	if err != nil {
		return err
	}
	switch command {
	case "list":
		out := flagValue(rest, "--output", "")
		return writeOrPrintJSON(out, map[string]any{"protocol": extensionCLIProtocol0209, "items": items})
	case "run":
		pos := extensionCLIPositionals0209(rest)
		if len(pos) < 2 {
			return errors.New("расширение CLI запуск требует <пространство имён> <команда> [-- args...]")
		}
		argv := afterDoubleDash0209(rest)
		return invokeExtensionNamespace0209(backend, token, items, pos[0], pos[1], flagValue(rest, "--scope", "global"), flagValue(rest, "--scope-id", ""), argv)
	case "completion":
		pos := extensionCLIPositionals0209(rest)
		shell := "bash"
		if len(pos) > 0 {
			shell = strings.ToLower(pos[0])
		}
		script, err := extensionCLICompletion0209(shell, items, backend)
		if err != nil {
			return err
		}
		fmt.Print(script)
		return nil
	default:
		return fmt.Errorf("неизвестная расширение CLI подкоманда: %s", command)
	}
}

func handleExtensionNamespace0209(args []string) error {
	backend := adminBackendURL(args)
	if backend == "" {
		return errors.New("nl x требует --серверная часть <URL>")
	}
	token := backendToken(args)
	if token == "" {
		return errors.New("nl x требует --токен или NEVERLAUNCHER_TOKEN")
	}
	pos := extensionCLIPositionals0209(args)
	if len(pos) < 2 {
		return errors.New("использование: nl x <пространство имён> <команда> [--область глобальный|проект] [--область-ID ID] [-- args...]")
	}
	items, err := fetchExtensionCLICatalog0209(backend, token)
	if err != nil {
		return err
	}
	return invokeExtensionNamespace0209(backend, token, items, pos[0], pos[1], flagValue(args, "--scope", "global"), flagValue(args, "--scope-id", ""), afterDoubleDash0209(args))
}

func extensionCLIPositionals0209(args []string) []string {
	out := []string{}
	takesValue := map[string]bool{"--backend": true, "--token": true, "--scope": true, "--scope-id": true, "--output": true}
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			break
		}
		if strings.HasPrefix(args[i], "--") {
			if strings.Contains(args[i], "=") {
				continue
			}
			if takesValue[args[i]] && i+1 < len(args) {
				i++
			}
			continue
		}
		out = append(out, args[i])
	}
	return out
}
func afterDoubleDash0209(args []string) []string {
	for i, v := range args {
		if v == "--" {
			return append([]string(nil), args[i+1:]...)
		}
	}
	return nil
}

func invokeExtensionNamespace0209(backend, token string, items []extensionCLICatalogItem0209, namespace, command, scope, scopeID string, argv []string) error {
	namespace = strings.ToLower(strings.TrimSpace(namespace))
	command = strings.ToLower(strings.TrimSpace(command))
	scope = strings.ToLower(strings.TrimSpace(scope))
	if scope == "" {
		scope = "global"
	}
	if scope != "global" && scope != "project" {
		return errors.New("--область должен быть глобальный или проект")
	}
	if scope == "global" {
		scopeID = ""
	} else if strings.TrimSpace(scopeID) == "" {
		return errors.New("--область проект требует --область-ID")
	}
	matches := []extensionCLICatalogItem0209{}
	for _, item := range items {
		if item.CLI.Namespace == namespace && item.Scope == scope && (scope != "project" || item.ScopeID == scopeID) {
			matches = append(matches, item)
		}
	}
	if len(matches) == 0 {
		return fmt.Errorf("CLI пространство имён %q не найден для область %s/%s", namespace, scope, scopeID)
	}
	if len(matches) > 1 {
		return fmt.Errorf("CLI пространство имён %q неоднозначен; укажите --scope/--scope-id", namespace)
	}
	item := matches[0]
	declared := false
	for _, c := range item.CLI.Commands {
		if c.Name == command {
			declared = true
			break
		}
	}
	if !declared {
		return fmt.Errorf("пространство имён %s не объявляет команду %s", namespace, command)
	}
	body := map[string]any{"scope": scope, "scopeId": scopeID, "command": command, "args": argv}
	data, _ := json.Marshal(body)
	endpoint := backend + "/api/v1/admin/extension-cli/" + url.PathEscape(item.ExtensionID) + "/invoke"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	client := http.Client{Timeout: 65 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return err
	}
	var envelope struct {
		Data struct {
			ExitCode int    `json:"exitCode"`
			Stdout   string `json:"stdout"`
			Stderr   string `json:"stderr"`
		} `json:"data"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("недопустимый CLI расширение ответ: %w", err)
	}
	if envelope.Data.Stdout != "" {
		fmt.Print(envelope.Data.Stdout)
		if !strings.HasSuffix(envelope.Data.Stdout, "\n") {
			fmt.Println()
		}
	}
	if envelope.Data.Stderr != "" {
		fmt.Fprint(os.Stderr, envelope.Data.Stderr)
		if !strings.HasSuffix(envelope.Data.Stderr, "\n") {
			fmt.Fprintln(os.Stderr)
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := envelope.Error.Message
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("расширение команда ошибка: %s", msg)
	}
	if envelope.Data.ExitCode != 0 {
		return fmt.Errorf("расширение команда выход с код %d", envelope.Data.ExitCode)
	}
	return nil
}

func extensionCLICompletion0209(shell string, items []extensionCLICatalogItem0209, backend string) (string, error) {
	namespaces := map[string][]string{}
	for _, item := range items {
		for _, c := range item.CLI.Commands {
			namespaces[item.CLI.Namespace] = append(namespaces[item.CLI.Namespace], c.Name)
		}
	}
	keys := make([]string, 0, len(namespaces))
	for k := range namespaces {
		sort.Strings(namespaces[k])
		keys = append(keys, k)
	}
	sort.Strings(keys)
	switch shell {
	case "bash":
		var b strings.Builder
		b.WriteString("# generated by nl extension cli completion bash\n_nl_ext(){ local cur ns; COMPREPLY=(); cur=\"${COMP_WORDS[COMP_CWORD]}\"; ns=\"${COMP_WORDS[2]}\"; if [[ $COMP_CWORD -eq 2 ]]; then COMPREPLY=( $(compgen -W '")
		b.WriteString(strings.Join(keys, " "))
		b.WriteString("' -- \"$cur\") ); return; fi; case \"$ns\" in\n")
		for _, k := range keys {
			fmt.Fprintf(&b, "  %s) COMPREPLY=( $(compgen -W '%s' -- \"$cur\") ) ;;\n", k, strings.Join(namespaces[k], " "))
		}
		b.WriteString("esac; }\ncomplete -F _nl_ext nl\n")
		return b.String(), nil
	case "zsh":
		var b strings.Builder
		b.WriteString("# generated by nl extension cli completion zsh\n# namespaces available through `nl x`: ")
		b.WriteString(strings.Join(keys, " "))
		b.WriteString("\n")
		for _, k := range keys {
			fmt.Fprintf(&b, "# %s: %s\n", k, strings.Join(namespaces[k], " "))
		}
		return b.String(), nil
	case "fish":
		var b strings.Builder
		for _, k := range keys {
			fmt.Fprintf(&b, "complete -c nl -n '__fish_seen_subcommand_from x' -a '%s'\n", k)
			for _, c := range namespaces[k] {
				fmt.Fprintf(&b, "complete -c nl -n '__fish_seen_subcommand_from %s' -a '%s'\n", k, c)
			}
		}
		return b.String(), nil
	default:
		return "", fmt.Errorf("завершение оболочка должен быть bash, zsh или fish (серверная часть %s)", backend)
	}
}
