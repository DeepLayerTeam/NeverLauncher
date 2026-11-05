// Package gravitidentity извлекает записи идентичности из настоящего Gravit
// FileAuthSystem Database.json и явных снимков SQL CSV без исполнения модулей или
// импорта учётных данных. Он никогда не выводит UUID из имён.
package gravitidentity

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
	"regexp"
	"sort"
	"strings"

	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
)

const Format = "launcher.gravit-identity-map.v1"
const MaxAccounts = 200000
const MaxIdentityFile = 64 << 20

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{3,16}$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type Account struct {
	Provider   string `json:"provider"`
	SourceID   string `json:"sourceId"`
	Username   string `json:"username"`
	UUID       string `json:"uuid"`
	SourcePath string `json:"sourcePath"`
}
type Mapping struct {
	Account
	TargetUserID string `json:"targetUserId,omitempty"`
	Status       string `json:"status"` // matched, pending_import, blocked
	Reason       string `json:"reason"`
}
type Report struct {
	Format          string         `json:"format"`
	RunID           string         `json:"runId"`
	SourceSHA256    string         `json:"sourceSha256"`
	InventorySHA256 string         `json:"inventorySha256"`
	EntriesSHA256   string         `json:"entriesSha256"`
	Rows            []Mapping      `json:"rows"`
	Summary         map[string]int `json:"summary"`
	Ready           bool           `json:"ready"` // Все UUID совпали; это НЕ разрешает переключение.
}

func UUID(s string) (string, error) {
	s = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), "-", ""))
	if !uuidPattern.MatchString(s) || s == strings.Repeat("0", 32) {
		return "", errors.New("Некорректный UUID Minecraft")
	}
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}
func normalized(a Account) (Account, error) {
	if !usernamePattern.MatchString(a.Username) {
		return a, fmt.Errorf("Некорректное значение: имя пользователя Minecraft %q", a.Username)
	}
	if a.SourceID == "" || len(a.SourceID) > 256 || strings.TrimSpace(a.SourceID) != a.SourceID {
		return a, errors.New("Отсутствует или неверен стабильный ID исходной учётной записи")
	}
	var e error
	a.UUID, e = UUID(a.UUID)
	return a, e
}

// StrictRootMap отклоняет повторяющиеся JSON-ключи в корне — частую причину
// незаметной перезаписи аккаунтов в базах Java/Gson.
func strictRootMap(b []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return nil, errors.New("Ожидался JSON-словарь UUID FileAuth")
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		token, e := d.Token()
		if e != nil {
			return nil, e
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("Некорректное значение: ключ")
		}
		if _, exists := out[strings.ToLower(key)]; exists {
			return nil, fmt.Errorf("Обнаружен дубликат: «source identity key» %q", key)
		}
		var raw json.RawMessage
		if e = d.Decode(&raw); e != nil {
			return nil, e
		}
		out[strings.ToLower(key)] = raw
	}
	if _, e = d.Token(); e != nil {
		return nil, e
	}
	var extra any
	if e = d.Decode(&extra); e != io.EOF {
		return nil, errors.New("После JSON FileAuth обнаружены лишние данные")
	}
	return out, nil
}

// Отклоняйте дублирующиеся поля в каждом объекте пользователя: иначе
// encoding/json незаметно примет последнее имя или UUID, скрывая противоречивые
// идентичности.
func uniqueUserFields(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return errors.New("FileAuth user: требуется объект JSON")
	}
	seen := map[string]bool{}
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("Некорректное значение: «FileAuth user key»")
		}
		// encoding/json сопоставляет поля структур без учёта регистра. Отклоняйте
		// псевдонимы вроде username/USERNAME вместо неявного доверия последнему
		// значению, меняющему импортируемую идентичность.
		folded := strings.ToLower(key)
		if seen[folded] {
			return fmt.Errorf("Обнаружен дубликат: «FileAuth user field» %q", key)
		}
		seen[folded] = true
		var value json.RawMessage
		if err = dec.Decode(&value); err != nil {
			return err
		}
	}
	if _, err = dec.Token(); err != nil {
		return err
	}
	var trailing any
	if err = dec.Decode(&trailing); err != io.EOF {
		return errors.New("После полей пользователя FileAuth обнаружены лишние данные")
	}
	return nil
}

func parseFileAuth(b []byte, pathname string) ([]Account, error) {
	root, e := strictRootMap(b)
	if e != nil {
		return nil, e
	}
	if len(root) > MaxAccounts {
		return nil, errors.New("Превышено число учётных записей FileAuth")
	}
	accounts := make([]Account, 0, len(root))
	for key, raw := range root {
		if err := uniqueUserFields(raw); err != nil {
			return nil, fmt.Errorf("Пользователь FileAuth %s: %w", key, err)
		}
		var obj struct {
			Username string `json:"username"`
			UUID     string `json:"uuid"`
		}
		if e = json.Unmarshal(raw, &obj); e != nil {
			return nil, fmt.Errorf("Пользователь FileAuth %s: %w", key, e)
		}
		canonicalKey, e := UUID(key)
		if e != nil {
			return nil, fmt.Errorf("Ключ словаря FileAuth: %w", e)
		}
		if obj.UUID != "" {
			embedded, e := UUID(obj.UUID)
			if e != nil || canonicalKey != embedded {
				return nil, fmt.Errorf("Несоответствие UUID FileAuth для %q", key)
			}
		}
		a, e := normalized(Account{Provider: "fileauth", SourceID: canonicalKey, Username: obj.Username, UUID: canonicalKey, SourcePath: pathname})
		if e != nil {
			return nil, e
		}
		accounts = append(accounts, a)
	}
	return accounts, nil
}
func parseSQLCSV(b []byte, pathname string) ([]Account, error) {
	reader := csv.NewReader(bytes.NewReader(b))
	reader.FieldsPerRecord = -1
	reader.ReuseRecord = false
	header, e := reader.Read()
	if e != nil {
		return nil, e
	}
	cols := map[string]int{}
	for i, c := range header {
		c = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(c, "\ufeff")))
		if _, ok := cols[c]; ok {
			return nil, errors.New("Обнаружен дубликат: «SQL CSV column»")
		}
		cols[c] = i
	}
	// Столбцы SQL users в документации Gravit 5.7 настраиваются; SQL-экспорт
	// нормализуется оператором до id,username,uuid, а не угадывается по SQL.
	for _, c := range []string{"id", "username", "uuid"} {
		if _, ok := cols[c]; !ok {
			return nil, fmt.Errorf("В CSV SQL отсутствует столбец %s", c)
		}
	}
	out := []Account{}
	for row := 2; ; row++ {
		fields, e := reader.Read()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, fmt.Errorf("Строка %d CSV SQL: %w", row, e)
		}
		if len(fields) != len(header) {
			return nil, fmt.Errorf("Строка %d CSV SQL: неожиданное число столбцов", row)
		}
		a, e := normalized(Account{Provider: "sql", SourceID: fields[cols["id"]], Username: fields[cols["username"]], UUID: fields[cols["uuid"]], SourcePath: pathname})
		if e != nil {
			return nil, fmt.Errorf("Строка %d CSV SQL: %w", row, e)
		}
		out = append(out, a)
		if len(out) > MaxAccounts {
			return nil, errors.New("Слишком много учётных записей SQL")
		}
	}
	return out, nil
}

// Extract читает полный исходный архив и только распознанные местоположения
// аккаунтов. Пароли, токены, права и поля сессий отбрасываются. Точные байты ZIP
// должны быть уже связаны с устойчивой инвентаризацией 0.33.3.
func Extract(ctx context.Context, src io.ReaderAt, size int64, snapshot inv.Inventory) ([]Account, error) {
	checked, e := inv.Inspect(ctx, src, size, snapshot.SourceSHA256)
	if e != nil {
		return nil, e
	}
	if checked.ManifestSHA256 != snapshot.ManifestSHA256 || checked.SourceBytes != snapshot.SourceBytes {
		return nil, errors.New("Исходный архив изменился после инвентаризации")
	}
	z, e := zip.NewReader(src, size)
	if e != nil {
		return nil, e
	}
	var accounts []Account
	selected := 0
	for _, f := range z.File {
		name := strings.ToLower(f.Name)
		isFileAuth := strings.HasSuffix(name, "/database.json") && (strings.Contains(name, "fileauthsystem/") || strings.Contains(name, "fileauth/"))
		isSQL := name == "sql-export/users.csv" || strings.HasSuffix(name, "/sql-export/users.csv")
		if !isFileAuth && !isSQL {
			continue
		}
		selected++
		if f.UncompressedSize64 > MaxIdentityFile {
			return nil, fmt.Errorf("Превышен допустимый размер: «identity source» %q", f.Name)
		}
		r, e := f.Open()
		if e != nil {
			return nil, e
		}
		b, e := io.ReadAll(io.LimitReader(r, MaxIdentityFile+1))
		closeErr := r.Close()
		if e != nil {
			return nil, e
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if int64(len(b)) > MaxIdentityFile {
			return nil, errors.New("Превышен лимит исходных учётных записей")
		}
		var parsed []Account
		if isFileAuth {
			parsed, e = parseFileAuth(b, f.Name)
		} else {
			parsed, e = parseSQLCSV(b, f.Name)
		}
		if e != nil {
			return nil, fmt.Errorf("%s: %w", f.Name, e)
		}
		accounts = append(accounts, parsed...)
		if len(accounts) > MaxAccounts {
			return nil, errors.New("Слишком много исходных учётных записей")
		}
	}
	if selected == 0 {
		return nil, errors.New("Отсутствует: «supported FileAuthSystem/Database.json or sql-export/users.csv identity snapshot found»")
	}
	if len(accounts) == 0 {
		return nil, errors.New("Снимок исходных учётных записей не содержит аккаунтов")
	}
	sort.Slice(accounts, func(i, j int) bool {
		a, b := accounts[i], accounts[j]
		if a.Provider != b.Provider {
			return a.Provider < b.Provider
		}
		if a.SourceID != b.SourceID {
			return a.SourceID < b.SourceID
		}
		return a.SourcePath < b.SourcePath
	})
	return accounts, nil
}
func Digest(accounts []Account) (string, error) {
	b, e := json.Marshal(accounts)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

type Target struct {
	UserID   string
	Username string
	UUID     string
	Source   string
}

// Reconcile обнаруживает дубли идентичностей источника и конфликты во всём
// пространстве идентичностей Never. Одно имя НИКОГДА не является доказательством
// привязки.
func Reconcile(accounts []Account, targets []Target) ([]Mapping, map[string]int) {
	byUUID := map[string][]Target{}
	byName := map[string][]Target{}
	dedup := map[string]bool{}
	for _, t := range targets {
		u, e := UUID(t.UUID)
		if e != nil {
			continue
		}
		t.UUID = u
		// Проверенная официальная привязка может отражать тот же локальный профиль
		// Minecraft. Объединяются только записи с одинаковыми владением и именем,
		// никогда противоречивые утверждения.
		key := u + "\x00" + t.UserID + "\x00" + strings.ToLower(t.Username)
		if dedup[key] {
			continue
		}
		dedup[key] = true
		byUUID[u] = append(byUUID[u], t)
		byName[strings.ToLower(t.Username)] = append(byName[strings.ToLower(t.Username)], t)
	}
	seenID := map[string]int{}
	seenUUID := map[string]int{}
	seenName := map[string]int{}
	for _, a := range accounts {
		seenID[a.Provider+"\x00"+a.SourceID]++
		seenUUID[a.UUID]++
		seenName[strings.ToLower(a.Username)]++
	}
	rows := make([]Mapping, 0, len(accounts))
	sum := map[string]int{"matched": 0, "pending_import": 0, "blocked": 0}
	for _, a := range accounts {
		m := Mapping{Account: a, Status: "pending_import", Reason: "Нет соответствующей учётной записи Never; зарезервировано для последующего импорта с подтверждением подлинности"}
		switch {
		case seenID[a.Provider+"\x00"+a.SourceID] > 1:
			m.Status = "blocked"
			m.Reason = "duplicate source provider ID"
		case seenUUID[a.UUID] > 1:
			m.Status = "blocked"
			m.Reason = "duplicate source UUID across account records"
		case seenName[strings.ToLower(a.Username)] > 1:
			m.Status = "blocked"
			m.Reason = "ambiguous source username (case-insensitive)"
		default:
			uuidOwners := byUUID[a.UUID]
			nameOwners := byName[strings.ToLower(a.Username)]
			if len(uuidOwners) > 1 || len(nameOwners) > 1 {
				m.Status = "blocked"
				m.Reason = "Несколько учётных записей Never претендуют на один UUID или имя пользователя"
			} else if len(uuidOwners) == 1 {
				owner := uuidOwners[0]
				if !strings.EqualFold(owner.Username, a.Username) || (len(nameOwners) == 1 && nameOwners[0].UserID != owner.UserID) {
					m.Status = "blocked"
					m.Reason = "Never UUID ownership/name collision"
				} else {
					m.TargetUserID = owner.UserID
					m.Status = "matched"
					m.Reason = "UUID и имя пользователя Never совпадают; перед переключением необходимо повторно проверить владение целевой учётной записью"
				}
			} else if len(nameOwners) != 0 {
				m.Status = "blocked"
				m.Reason = "Имя пользователя уже связано с другим UUID Never"
			}
		}
		sum[m.Status]++
		rows = append(rows, m)
	}
	return rows, sum
}
