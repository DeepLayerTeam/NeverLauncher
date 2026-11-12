package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func migrationModuleEndpoint0338(endpoint string) error {
	u, e := url.Parse(endpoint)
	if e != nil {
		return e
	}
	if u.Scheme == "https" {
		return nil
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme == "http" && ip != nil && ip.IsLoopback() {
		return nil
	}
	return errors.New("Загрузка модуля Gravit: требуется HTTPS или IP-адрес обратной связи")
}
func migrationModuleAnalyze0338(endpoint, token, source, out string) error {
	if err := migrationModuleEndpoint0338(endpoint); err != nil {
		return err
	}
	f, err := os.Open(source)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > 512<<20 {
		return errors.New("Ожидается обычный ZIP-файл источника размером от 1 до 512 МиБ")
	}
	req, err := http.NewRequest("POST", endpoint, f)
	if err != nil {
		return err
	}
	req.ContentLength = st.Size()
	req.Header.Set("Content-Type", "application/zip")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	client := &http.Client{Timeout: 45 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("Ошибка HTTP %d при проверке модуля: %s", resp.StatusCode, raw)
	}
	var parsed any
	if err = json.Unmarshal(raw, &parsed); err != nil {
		return err
	}
	if out != "" {
		return writePrivateIdentityReport0334(out, parsed)
	}
	fmt.Println(string(raw))
	return nil
}
func migrationModuleEnroll0338(endpoint, token, run, out, wrapper, id, name, kind, profile, key string, fresh bool) error {
	if err := migrationModuleEndpoint0338(endpoint); err != nil {
		return err
	}
	if !fresh {
		return errors.New("Требуется --fresh-keys-confirmed: новая независимая пара ключей Ed25519 Launcher")
	}
	if run == "" || wrapper == "" || id == "" || kind == "" || profile == "" || key == "" {
		return errors.New("Требуется: --run --wrapper --server-id --kind --profile-id --public-key")
	}
	body := map[string]string{"wrapperPath": wrapper, "id": id, "name": name, "kind": kind, "profileId": profile, "publicKey": key}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Migration-Modules-Confirm", run)
	req.Header.Set("X-Migration-Fresh-Keys-Confirmed", "true")
	client := &http.Client{Timeout: 90 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("Ошибка HTTP %d при регистрации ServerBridge: %s", resp.StatusCode, answer)
	}
	var parsed any
	if err = json.Unmarshal(answer, &parsed); err != nil {
		return err
	}
	if out != "" {
		return writePrivateIdentityReport0334(out, parsed)
	}
	fmt.Println(string(answer))
	return nil
}

// Проверяйте реальное подписанное состояние Runtime ServerBridge для перенесённой оболочки. Одной
// сохранённой квитанции регистрации недостаточно для подтверждения готовности игры.
func migrationBridgeStatus0446(endpoint, token, wrapper, out string) error {
	if wrapper == "" {
		return errors.New("Требуется: --wrapper")
	}
	if err := migrationModuleEndpoint0338(endpoint); err != nil {
		return err
	}
	req, err := http.NewRequest("GET", endpoint+"?wrapperPath="+url.QueryEscape(wrapper), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("Статус ServerBridge: HTTP %d: %s", resp.StatusCode, raw)
	}
	var payload struct {
		Data struct {
			State    string `json:"state"`
			Reason   string `json:"reason"`
			ServerID string `json:"serverId"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return err
	}
	if payload.Data.ServerID == "" || payload.Data.State == "" {
		return errors.New("Отсутствует актуальное состояние ServerBridge")
	}
	if out != "" {
		if err = writePrivateIdentityReport0334(out, payload); err != nil {
			return err
		}
	} else {
		fmt.Println(string(raw))
	}
	if payload.Data.State != "online" {
		return fmt.Errorf("ServerBridge недоступен: %s (%s)", payload.Data.State, payload.Data.Reason)
	}
	return nil
}
