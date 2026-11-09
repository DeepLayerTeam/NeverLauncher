package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// CLI читает полный актуальный снимок, независимо экспортированный из ограждённого
// производственного развёртывания. Он никогда не подделывает неизменённые данные игроков.
func handleMigrationRollback03312(args []string) error {
	if len(args) == 0 {
		return errors.New("Откат: требуется «rollback-plan|rollback-commit|rollback-status»")
	}
	cmd := args[0]
	backend := strings.TrimRight(flagValue(args, "--backend", ""), "/")
	run := flagValue(args, "--run", "")
	token := backendToken(args)
	if backend == "" || run == "" || token == "" {
		return errors.New("Откат: требуется --backend --run --token")
	}
	u, e := url.Parse(backend)
	if e != nil {
		return e
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return errors.New("Откат: требуется HTTPS или локальный адрес обратной связи")
		}
	}
	path := backend + "/api/v1/admin/migration-runs/" + url.PathEscape(run) + "/rollbacks"
	if cmd == "rollback-status" {
		return cutoverRequest03311("GET", path+"/"+url.PathEscape(flagValue(args, "--profile-id", ""))+"/"+url.PathEscape(flagValue(args, "--channel", "")), token, run, nil, false, flagValue(args, "--output", ""))
	}
	if flagValue(args, "--confirm", "") != run || flagValue(args, "--writer-fenced", "") != "true" {
		return errors.New("Откат: требуется точный идентификатор запуска --confirm и --writer-fenced true")
	}
	revision, e := strconv.ParseInt(flagValue(args, "--expected-revision", ""), 10, 64)
	if e != nil || revision < 1 {
		return errors.New("Откат: требуется положительный номер --expected-revision")
	}
	body := map[string]any{"profileId": flagValue(args, "--profile-id", ""), "channel": flagValue(args, "--channel", ""), "expectedRevision": revision}
	switch cmd {
	case "rollback-plan", "rollback-commit":
		file := flagValue(args, "--snapshot", "")
		if file == "" {
			return errors.New("Откат: требуется «--snapshot JSON from independently fenced live deployment»")
		}
		snapshot, snapshotHash, e := rollbackReadSnapshot0448(file)
		if e != nil {
			return e
		}
		body["current"] = snapshot
		sourceFile := flagValue(args, "--reconciled-source-snapshot", "")
		if sourceFile != "" {
			data, _, err := rollbackReadSnapshot0448(sourceFile)
			if err != nil {
				return err
			}
			body["reconciledSource"] = data
			body["reconciliationEvidenceSha256"] = flagValue(args, "--reconciliation-evidence-sha256", "")
		}
		if cmd == "rollback-plan" {
			body["evidenceReference"] = flagValue(args, "--evidence-reference", file)
			if expected := flagValue(args, "--evidence-sha256", ""); expected != "" && expected != snapshotHash {
				return errors.New("SHA-256 файла снимка не совпадает с SHA-256 доказательства отката")
			}
			body["evidenceSha256"] = snapshotHash
			path += "/plan"
		} else {
			if flagValue(args, "--source-writer-fenced", "") != "true" {
				return errors.New("commit: требуется независимо заблокированный процесс записи источника")
			}
			body["planSha256"] = flagValue(args, "--plan-sha256", "")
			body["sourceWriterFenced"] = true
			body["neverWriterFenced"] = true
			if expected := flagValue(args, "--current-evidence-sha256", ""); expected != "" && expected != snapshotHash {
				return errors.New("SHA-256 нового снимка не совпадает с доказательством отката")
			}
			body["currentEvidenceSha256"] = snapshotHash
			path += "/commit"
		}
	default:
		return errors.New("Неизвестное значение: команда отката")
	}
	// Повторно используйте производственный HTTP-клиент с тайм-аутами и отключёнными перенаправлениями. В
	// отличие от MIG11 здесь обязательны оба дополнительных заголовка ограждения.
	raw, _ := json.Marshal(body)
	req, e := http.NewRequest("POST", path, strings.NewReader(string(raw)))
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Migration-Rollback-Confirm", run)
	req.Header.Set("X-Writer-Fenced", "true")
	if cmd == "rollback-commit" {
		req.Header.Set("X-Migration-Source-Fenced", "true")
	}
	return rollbackSend03312(req, flagValue(args, "--output", ""))
}

// rollbackReadSnapshot0448 хеширует ТОЧНЫЕ байты, отправленные серверу, исключая гонку
// TOCTOU при повторном чтении файла оператора. Никогда не используйте произвольный
// --evidence-sha256 для разрешения нового плана отката.
func rollbackReadSnapshot0448(path string) (any, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, "", err
	}
	if !st.Mode().IsRegular() || st.Size() == 0 || st.Size() > 8<<20 {
		return nil, "", errors.New("Для снимка отката требуется обычный JSON-файл размером не более 8 МиБ")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (8<<20)+1))
	if err != nil {
		return nil, "", err
	}
	if len(raw) > 8<<20 {
		return nil, "", errors.New("Снимок отката превышает 8 МиБ")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var snapshot any
	if err = d.Decode(&snapshot); err != nil {
		return nil, "", err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, "", errors.New("Снимок содержит лишние данные")
	}
	sum := sha256.Sum256(raw)
	return snapshot, hex.EncodeToString(sum[:]), nil
}
