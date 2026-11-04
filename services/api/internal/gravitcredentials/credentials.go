// Package gravitcredentials импортирует только явно поддерживаемые верификаторы
// паролей Gravit из уже инвентаризированного неизменяемого ZIP. Секреты не
// попадают в отчёты; старые сессии, разрешения и ключи никогда не импортируются.
package gravitcredentials

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/fileauth"
	gi "gitflic.ru/skif4er/launcher/services/api/internal/gravitidentity"
	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
)

const Format = "launcher.gravit-credentials.v1"

type Credential struct {
	gi.Account
	PasswordHash string `json:"-"` // Only ever passed to the SQL insert; never serialize.
	Algorithm    string `json:"algorithm"`
	State        string `json:"state"` // importable, manual_reset
	Reason       string `json:"reason,omitempty"`
}

type Result struct {
	Format            string `json:"format"`
	RunID             string `json:"runId"`
	SourceSHA256      string `json:"sourceSha256"`
	IdentitySHA256    string `json:"identitySha256"`
	Imported          int    `json:"imported"`
	ExistingUnchanged int    `json:"existingUnchanged"`
	ManualReset       int    `json:"manualReset"`
	Complete          bool   `json:"complete"`
	DryRun            bool   `json:"dryRun"` // Credential processing only, not permission for cutover.
	Rows              []Row  `json:"rows"`
}

type Row struct {
	Provider string `json:"provider"`
	SourceID string `json:"sourceId"`
	Username string `json:"username"`
	UUID     string `json:"uuid"`
	State    string `json:"state"`
	Reason   string `json:"reason,omitempty"`
}

// Extract всегда повторно проверяет весь источник по инвентаризации 0.33.3 и
// извлекает карту идентичностей 0.33.4 перед чтением хешей паролей. Источник не
// может незаметно добавить или изменить учётные данные после сопоставления.
func Extract(ctx context.Context, source io.ReaderAt, size int64, inventory inv.Inventory, fileauthFormat string) ([]Credential, error) {
	identities, err := gi.Extract(ctx, source, size, inventory)
	if err != nil {
		return nil, err
	}
	expected := map[string]gi.Account{}
	for _, a := range identities {
		expected[a.Provider+"\x00"+a.SourcePath+"\x00"+a.SourceID] = a
	}
	z, err := zip.NewReader(source, size)
	if err != nil {
		return nil, err
	}
	out := make([]Credential, 0, len(identities))
	for _, f := range z.File {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := strings.ToLower(f.Name)
		isFile := strings.HasSuffix(name, "/database.json") && (strings.Contains(name, "fileauthsystem/") || strings.Contains(name, "fileauth/"))
		isSQL := name == "sql-export/users.csv" || strings.HasSuffix(name, "/sql-export/users.csv")
		if !isFile && !isSQL {
			continue
		}
		if f.UncompressedSize64 > gi.MaxIdentityFile {
			return nil, fmt.Errorf("credential source %q is too large", f.Name)
		}
		rc, e := f.Open()
		if e != nil {
			return nil, e
		}
		data, e := io.ReadAll(io.LimitReader(rc, gi.MaxIdentityFile+1))
		closeErr := rc.Close()
		if e != nil {
			return nil, e
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if len(data) > gi.MaxIdentityFile {
			return nil, errors.New("credential file overflow")
		}
		if isFile {
			// Используйте точный набор UUID/имён, уже проверенный gravitidentity. Старый
			// парсер FileAuth ограничен 16 МиБ и 20 тысячами пользователей, а
			// инвентаризация поддерживает 64 МиБ и 200 тысяч. Повторный разбор со слабее
			// установленными пределами отклонил бы допустимые снимки миграции.
			// Неизвестные алгоритмы хеширования явно помечаются для сброса, а не
			// угадываются.
			accounts, e := parseFileAuthCredentials(data, f.Name, fileauthFormat, expected)
			if e != nil {
				return nil, fmt.Errorf("FileAuth %s: %w", f.Name, e)
			}
			out = append(out, accounts...)
		} else {
			rows, e := parseSQL(data, f.Name)
			if e != nil {
				return nil, e
			}
			out = append(out, rows...)
		}
	}
	if len(out) != len(identities) {
		return nil, errors.New("credential records differ from verified identity inventory")
	}
	seen := map[string]bool{}
	for _, c := range out {
		key := c.Provider + "\x00" + c.SourcePath + "\x00" + c.SourceID
		a, ok := expected[key]
		if !ok || a.Username != c.Username || a.UUID != c.UUID || seen[key] {
			return nil, fmt.Errorf("credential identity differs from approved map: %s/%s", c.Provider, c.SourceID)
		}
		seen[key] = true
	}
	return out, nil
}

// parseFileAuthCredentials извлекает верификаторы паролей только для идентичностей
// из независимо проверенной карты MIG04. Роли, сессии, email и произвольные
// утверждения Gravit не принимаются. Неизвестные форматы хеша никогда не становятся
// действительными для входа.
func parseFileAuthCredentials(data []byte, path, format string, expected map[string]gi.Account) ([]Credential, error) {
	if format != "" && !fileauth.SupportedFormat(format) {
		return nil, errors.New("unsupported FileAuth password format")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errors.New("FileAuth Database.json must be a UUID-keyed object")
	}
	out := []Credential{}
	seen := make(map[string]bool)
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, err
		}
		rawUUID, ok := key.(string)
		if !ok {
			return nil, errors.New("non-string FileAuth identity key")
		}
		uuid, err := gi.UUID(rawUUID)
		if err != nil || seen[uuid] {
			return nil, errors.New("invalid or duplicate FileAuth UUID")
		}
		seen[uuid] = true
		account, ok := expected["fileauth\x00"+path+"\x00"+uuid]
		if !ok {
			return nil, errors.New("FileAuth UUID not found in verified identity map")
		}
		// MIG04 отклоняет повторяющиеся ключи в каждом объекте пользователя.
		// Переиспользуйте этот проверенный источник, декодируя здесь только поле
		// верификатора.
		var user struct {
			Password string `json:"password"`
		}
		if err = dec.Decode(&user); err != nil {
			return nil, err
		}
		c := Credential{Account: account, State: "manual_reset", Reason: "FileAuth verifier format is not selected; account requires a verified reset"}
		if format != "" {
			if user.Password == "" {
				c.Reason = "FileAuth password verifier is missing; account requires a verified reset"
			} else {
				c.PasswordHash, err = fileauth.EncodeCredential(format, user.Password)
				if err != nil {
					return nil, fmt.Errorf("invalid %s verifier for source UUID %s: %w", format, uuid, err)
				}
				c.Algorithm = format
				c.State, c.Reason = "importable", ""
			}
		}
		out = append(out, c)
		if len(out) > gi.MaxAccounts {
			return nil, errors.New("too many FileAuth accounts")
		}
	}
	if end, err := dec.Token(); err != nil || end != json.Delim('}') {
		return nil, errors.New("invalid FileAuth JSON terminator")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("trailing FileAuth JSON data")
	}
	return out, nil
}

func parseSQL(data []byte, path string) ([]Credential, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	header, e := r.Read()
	if e != nil {
		return nil, e
	}
	cols := map[string]int{}
	for i, s := range header {
		s = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(s, "\ufeff")))
		if _, ok := cols[s]; ok {
			return nil, errors.New("duplicate SQL credential column")
		}
		cols[s] = i
	}
	for _, field := range []string{"id", "username", "uuid"} {
		if _, ok := cols[field]; !ok {
			return nil, fmt.Errorf("missing SQL %s", field)
		}
	}
	out := []Credential{}
	for line := 2; ; line++ {
		rec, e := r.Read()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, fmt.Errorf("SQL row %d: %w", line, e)
		}
		if len(rec) != len(header) {
			return nil, fmt.Errorf("SQL row %d column mismatch", line)
		}
		uuid, e := gi.UUID(rec[cols["uuid"]])
		if e != nil {
			return nil, fmt.Errorf("SQL row %d: %w", line, e)
		}
		c := Credential{Account: gi.Account{Provider: "sql", SourceID: rec[cols["id"]], Username: rec[cols["username"]], UUID: uuid, SourcePath: path}, State: "manual_reset", Reason: "no supported password verifier supplied"}
		fcol, hasF := cols["password_format"]
		hcol, hasH := cols["password_hash"]
		if hasF && hasH {
			c.Algorithm = strings.TrimSpace(rec[fcol])
			hash := rec[hcol]
			if fileauth.SupportedFormat(c.Algorithm) && hash != "" {
				c.PasswordHash, e = fileauth.EncodeCredential(c.Algorithm, hash)
				if e != nil {
					return nil, fmt.Errorf("invalid verifier in SQL row %d: %w", line, e)
				}
				c.State = "importable"
				c.Reason = ""
			} else if hash != "" && c.Algorithm != "" {
				c.Reason = "unsupported verifier; only this account requires transition or reset"
			}
		}
		out = append(out, c)
		if len(out) > gi.MaxAccounts {
			return nil, errors.New("too many SQL credentials")
		}
	}
	return out, nil
}

// SourceFingerprint — устойчивое к коллизиям связывание экспортированных байтов с
// явным решением о формате. Он не раскрывает хеш отдельного пароля.
func SourceFingerprint(sourceSHA, identitySHA, format string) string {
	h := sha256.Sum256([]byte(sourceSHA + "\x00" + identitySHA + "\x00" + format))
	return hex.EncodeToString(h[:])
}
