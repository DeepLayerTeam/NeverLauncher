// Пакет texturegravit переносит реальные записи Gravit TextureProvider в нормализованное хранилище текстур
// Launcher. Токены авторизации, закрытые URL, удалённые идентичности и непроверенные байты PNG
// импортируются.
package texturegravit

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
	"gitflic.ru/skif4er/launcher/services/api/internal/texturepng"
)

// SourceRow соответствует таблице textures официальной PostgreSQL-схемы GravitLauncher/TextureProvider.
// ObjectKey — доверенное расширение автономного экспорта; file_url загружается.
type SourceRow struct {
	ID          string          `json:"id"`
	UserUUID    string          `json:"user_uuid"`
	TextureType string          `json:"texture_type"`
	FileHash    string          `json:"file_hash"`
	FileURL     string          `json:"file_url"`
	Metadata    json.RawMessage `json:"metadata"`
	ObjectKey   string          `json:"object_key,omitempty"`
}

type Mapping struct {
	SourceUUID string `json:"source_uuid"`
	TargetUUID string `json:"target_uuid"`
}

type Record struct {
	ID               string `json:"id"`
	UUID             string `json:"sourceUuid,omitempty"`
	TargetUUID       string `json:"targetUuid,omitempty"`
	Kind             string `json:"kind,omitempty"`
	Status           string `json:"status"` // imported, already-imported, skipped-existing, unmatched, quarantined, blocked
	Reason           string `json:"reason,omitempty"`
	NormalizedDigest string `json:"normalizedDigest,omitempty"`
}

type Report struct {
	Format     string         `json:"format"`
	SourceID   string         `json:"sourceId"`
	DryRun     bool           `json:"dryRun"`
	StartedAt  time.Time      `json:"startedAt"`
	FinishedAt time.Time      `json:"finishedAt"`
	Counts     map[string]int `json:"counts"`
	PlanSHA256 string         `json:"planSha256"`
	FatalError string         `json:"fatalError,omitempty"`
	Rows       []Record       `json:"rows"`
}

type Database interface {
	GetMinecraftProfileByUUID(string) (model.MinecraftProfile, error)
	GravitImportState02510(context.Context, string, string, model.MinecraftProfile, string) (bool, int64, bool, error)
	StageTextureUpload0253(context.Context, model.MinecraftProfile, repository.VerifiedTexture0252) error
	UploadTexture0252(context.Context, model.MinecraftProfile, repository.VerifiedTexture0252) (model.TextureAssignment0251, error)
}

type Source interface {
	Open(context.Context, string) (io.ReadCloser, error)
}

type Runner struct {
	Database       Database
	Destination    storage.Storage
	Source         Source
	SourceID       string
	Mapping        map[string]string // exact source UUID -> administrator-confirmed local UUID
	ObjectTemplate string            // e.g. skins/%hash%.png or %kind%/%hash%.png
	Replace        bool              // только оператор с явным разрешением вправе перезаписать существующее локальное назначение
	DryRun         bool
}

var shaHex = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
var uuidHex = regexp.MustCompile(`^[0-9a-f]{32}$`)
var sourceIDFormat = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,99}$`)

func CanonicalUUID(raw string) (string, error) {
	s := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), "-", ""))
	if !uuidHex.MatchString(s) {
		return "", errors.New("Некорректное значение: источник UUID Minecraft")
	}
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}

func LoadMappings(data []byte) (map[string]string, error) {
	var rows []Mapping
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, err
	}
	if rows == nil || len(rows) > 100000 {
		return nil, errors.New("Ожидался непустой массив сопоставлений без null, максимум 100000 записей")
	}
	result := make(map[string]string, len(rows))
	reverse := make(map[string]string, len(rows))
	for _, p := range rows {
		from, err := CanonicalUUID(p.SourceUUID)
		if err != nil {
			return nil, err
		}
		to, err := CanonicalUUID(p.TargetUUID)
		if err != nil {
			return nil, err
		}
		if old, ok := result[from]; ok && old != to {
			return nil, fmt.Errorf("Неоднозначное сопоставление для %s", from)
		}
		if prior, exists := reverse[to]; exists && prior != from {
			return nil, fmt.Errorf("Разные исходные UUID %s и %s соответствуют одному целевому UUID", prior, from)
		}
		result[from] = to
		reverse[to] = from
	}
	return result, nil
}

func LoadJSON(data []byte) ([]SourceRow, error) {
	if len(data) == 0 || len(data) > 32<<20 {
		return nil, errors.New("Экспорт источника: требуется «at most 32 MiB»")
	}
	var rows []SourceRow
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, fmt.Errorf("Ожидался JSON-массив текстур TextureProvider: %w", err)
	}
	if rows == nil || len(rows) > 100000 {
		return nil, errors.New("Ожидался массив TextureProvider без null, максимум 100000 записей")
	}
	return rows, nil
}

// ReadPostgres читает официальную схему TextureProvider без произвольных SQL-запросов и идентификаторов от
// вызывающего кода. Учётные данные БД остаются в процессе оператора и появляются в отчётах.
func ReadPostgres(ctx context.Context, db *sql.DB) ([]SourceRow, error) {
	rows, err := db.QueryContext(ctx, `SELECT id::text,user_uuid::text,texture_type,file_hash,file_url,COALESCE(metadata,'{}'::jsonb) FROM textures ORDER BY user_uuid,texture_type,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	output := make([]SourceRow, 0)
	for rows.Next() {
		if len(output) >= 100000 {
			return nil, errors.New("Слишком много исходных записей (максимум 100000)")
		}
		var r SourceRow
		if err = rows.Scan(&r.ID, &r.UserUUID, &r.TextureType, &r.FileHash, &r.FileURL, &r.Metadata); err != nil {
			return nil, err
		}
		output = append(output, r)
	}
	return output, rows.Err()
}

func ValidateObjectKey(key string) error {
	if key == "" || len(key) > 512 || strings.HasPrefix(key, "/") || strings.Contains(key, "\\") || strings.ContainsAny(key, "\x00\r\n") {
		return errors.New("Некорректное значение: «relative object key»")
	}
	for _, v := range strings.Split(key, "/") {
		if v == "" || v == "." || v == ".." {
			return errors.New("В ключе объекта обнаружен выход за пределы каталога либо пустой компонент")
		}
	}
	return nil
}

// RenderKey подставляет только строго проверенные хеш источника и тип, контролируемые импортёром. URL и
// имя хоста из file_url не используются как ключ S3.
func RenderKey(template, kind, hash string) (string, error) {
	if kind != "skin" && kind != "cape" || !shaHex.MatchString(hash) {
		return "", errors.New("Некорректное значение: текстура kind/hash")
	}
	if template == "" {
		template = "%kind%/%hash%.png"
	}
	key := strings.NewReplacer("%hash%", hash, "%kind%", kind, "%KIND%", strings.ToUpper(kind)).Replace(template)
	if strings.Contains(key, "%") {
		return "", errors.New("Неизвестное значение: «object-key template placeholder»")
	}
	return key, ValidateObjectKey(key)
}

func VerifySourceHash(hash string, b []byte) error {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if !shaHex.MatchString(hash) {
		return errors.New("Неизвестный формат контрольной суммы TextureProvider (ожидался SHA-1 или SHA-256)")
	}
	var sum string
	if len(hash) == 40 {
		v := sha1.Sum(b)
		sum = hex.EncodeToString(v[:])
	} else {
		v := sha256.Sum256(b)
		sum = hex.EncodeToString(v[:])
	}
	if sum != hash {
		return errors.New("Несовпадение: «source PNG digest»")
	}
	return nil
}

// PlanSHA256 привязывает утверждённый пробный запуск к точным строкам, сопоставлению идентичностей и
// параметрам импорта. Это дайджест источника и конфигурации, а не доказательство проверки PNG
// TextureProvider: её отдельно выполняет Run(dry-run=true). Входной file_url намеренно исключён, поскольку
// удалённые URL не загружаются. Канонический JSON сортирует ключи сопоставлений детерминированно.
func (r *Runner) PlanSHA256(rows []SourceRow) (string, error) {
	type safeRow struct {
		ID        string          `json:"id"`
		UserUUID  string          `json:"userUuid"`
		Kind      string          `json:"kind"`
		Hash      string          `json:"hash"`
		Metadata  json.RawMessage `json:"metadata"`
		ObjectKey string          `json:"objectKey"`
	}
	safe := make([]safeRow, 0, len(rows))
	for _, row := range rows {
		safe = append(safe, safeRow{row.ID, row.UserUUID, row.TextureType, row.FileHash, row.Metadata, row.ObjectKey})
	}
	b, err := json.Marshal(struct {
		Domain         string            `json:"domain"`
		SourceID       string            `json:"sourceId"`
		ObjectTemplate string            `json:"objectTemplate"`
		Replace        bool              `json:"replace"`
		Mapping        map[string]string `json:"mapping"`
		Rows           []safeRow         `json:"rows"`
	}{"never.gravit.texture-plan.0445", r.SourceID, r.ObjectTemplate, r.Replace, r.Mapping, safe})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func (r *Runner) Run(ctx context.Context, rows []SourceRow) (Report, error) {
	out := Report{Format: "launcher.gravit-texture-import.v1", SourceID: r.SourceID, DryRun: r.DryRun, StartedAt: time.Now().UTC(), Counts: map[string]int{}, Rows: make([]Record, 0, len(rows))}
	if !sourceIDFormat.MatchString(r.SourceID) || r.Database == nil || r.Source == nil || r.Destination == nil {
		return out, errors.New("Требуется: «source ID, source reader, destination and database»")
	}
	if len(rows) > 100000 {
		return out, errors.New("Слишком много строк с текстурами")
	}
	fingerprint, err := r.PlanSHA256(rows)
	if err != nil {
		return out, err
	}
	out.PlanSHA256 = fingerprint
	// Проверка должна предшествовать любым записям в БД или хранилище. Разные старые идентичности не должны
	// незаметно присваивать один профиль Never через явное или неявное сопоставление. Две исходные записи
	// также не должны одновременно стать одним выбором.
	if err := validateIdentityTargets(rows, r.Mapping); err != nil {
		out.FatalError = err.Error()
		out.FinishedAt = time.Now().UTC()
		return out, err
	}
	// Иначе дублирующиеся строки случайно обновят одно и то же назначение.
	seen := map[string]bool{}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			out.FatalError = err.Error()
			out.FinishedAt = time.Now().UTC()
			return out, err
		}
		rec := r.importOne(ctx, row, seen)
		out.Counts[rec.Status]++
		out.Rows = append(out.Rows, rec)
	}
	out.FinishedAt = time.Now().UTC()
	return out, nil
}

// validateIdentityTargets обеспечивает однозначное соответствие исходных и целевых идентичностей в пакете
// и не более одного скина и плаща на цель. Исходная схема может содержать старые дубликаты; произвольный
// выбор последней строки перезапишет назначение другого игрока, особенно с --replace.
func validateIdentityTargets(rows []SourceRow, mapping map[string]string) error {
	reverse := make(map[string]string)
	selections := make(map[string]string)
	rowIDs := make(map[string]struct{}, len(rows))
	for source, target := range mapping {
		from, err := CanonicalUUID(source)
		if err != nil || from != source {
			return errors.New("Сопоставление содержит исходный UUID в неканоническом формате")
		}
		to, err := CanonicalUUID(target)
		if err != nil || to != target {
			return errors.New("Сопоставление содержит целевой UUID в неканоническом формате")
		}
		if prev, ok := reverse[to]; ok && prev != from {
			return fmt.Errorf("Неоднозначный целевой UUID %s для %s и %s", to, prev, from)
		}
		reverse[to] = from
	}
	seenSource := make(map[string]string)
	for _, row := range rows {
		if _, ok := rowIDs[row.ID]; ok {
			return fmt.Errorf("Обнаружен дубликат: «TextureProvider row ID %q; no textures were imported»", row.ID)
		}
		rowIDs[row.ID] = struct{}{}
		from, err := CanonicalUUID(row.UserUUID)
		if err != nil {
			continue // для строки не найдено соответствие; целевой объект не может быть назначен
		}
		to := from
		if mapped, ok := mapping[from]; ok {
			to = mapped
		}
		if prev, ok := reverse[to]; ok && prev != from {
			return fmt.Errorf("Исходные UUID %s и %s указывают на один UUID Never %s", prev, from, to)
		}
		reverse[to] = from
		if prev, ok := seenSource[to]; ok && prev != from {
			return fmt.Errorf("Исходные UUID %s и %s указывают на один UUID Never %s", prev, from, to)
		}
		seenSource[to] = from
		kind := strings.ToLower(row.TextureType)
		if kind != "skin" && kind != "cape" {
			continue // per-row quarantined
		}
		key := to + "/" + kind
		if old, ok := selections[key]; ok && old != row.ID {
			return fmt.Errorf("Несколько записей %s (%s и %s) для целевого UUID %s; явно выберите одну до импорта", kind, old, row.ID, to)
		}
		selections[key] = row.ID
	}
	return nil
}

func (r *Runner) importOne(ctx context.Context, row SourceRow, seen map[string]bool) Record {
	rec := Record{ID: row.ID, UUID: row.UserUUID, Kind: strings.ToLower(row.TextureType), Status: "quarantined"}
	fail := func(status string, err error) Record { rec.Status = status; rec.Reason = err.Error(); return rec }
	if len(row.ID) < 1 || len(row.ID) > 150 {
		return fail("quarantined", errors.New("Некорректное значение: «or missing upstream row ID»"))
	}
	if rec.Kind != "skin" && rec.Kind != "cape" {
		return fail("quarantined", errors.New("Неизвестное значение: «TextureProvider texture type»"))
	}
	normalizedUUID, err := CanonicalUUID(row.UserUUID)
	if err != nil {
		return fail("unmatched", err)
	}
	if seen[row.ID] {
		return fail("quarantined", errors.New("Обнаружен дубликат: «upstream row ID»"))
	}
	seen[row.ID] = true
	target := normalizedUUID
	if dest, exists := r.Mapping[normalizedUUID]; exists {
		target = dest
	}
	rec.TargetUUID = target
	profile, err := r.Database.GetMinecraftProfileByUUID(target)
	if err != nil {
		return fail("unmatched", errors.New("Отсутствует: «verified local Minecraft profile for source UUID; explicit mapping required»"))
	}
	if profile.Realm != "local" || profile.Issuer != "launcher" || profile.UUID == "" || profile.UserID == "" {
		return fail("unmatched", errors.New("«official or non-local UUID»: запрещено «be imported»"))
	}
	if canonical, err := CanonicalUUID(profile.UUID); err != nil || canonical != target {
		return fail("unmatched", errors.New("UUID целевого профиля имеет неканонический формат"))
	}
	imported, rev, exists, err := r.Database.GravitImportState02510(ctx, r.SourceID, row.ID, profile, rec.Kind)
	if err != nil {
		return fail("blocked", err)
	}
	if imported {
		rec.Status = "already-imported"
		return rec
	}
	if exists && !r.Replace {
		return fail("skipped-existing", errors.New("Локальный выбор текстуры уже существует; для перезаписи явно укажите --replace"))
	}
	modelName := "classic"
	if len(row.Metadata) > 0 && string(row.Metadata) != "null" {
		var metadata map[string]json.RawMessage
		if err := json.Unmarshal(row.Metadata, &metadata); err != nil {
			return fail("quarantined", errors.New("Некорректное значение: «texture metadata JSON»"))
		}
		if raw, ok := metadata["model"]; ok {
			var name string
			if json.Unmarshal(raw, &name) != nil {
				return fail("quarantined", errors.New("Некорректное значение: «model metadata»"))
			}
			if strings.EqualFold(name, "slim") {
				if rec.Kind == "cape" {
					return fail("quarantined", errors.New("Для плаща нельзя выбрать модель slim"))
				}
				modelName = "slim"
			} else if name != "" && !strings.EqualFold(name, "default") && !strings.EqualFold(name, "classic") {
				return fail("quarantined", errors.New("Не поддерживается: модель скина"))
			}
		}
	}
	hash := strings.ToLower(strings.TrimSpace(row.FileHash))
	if !shaHex.MatchString(hash) {
		return fail("quarantined", errors.New("Не поддерживается: «or missing source hash»"))
	}
	key := row.ObjectKey
	if key == "" {
		key, err = RenderKey(r.ObjectTemplate, rec.Kind, hash)
		if err != nil {
			return fail("quarantined", err)
		}
	}
	if err := ValidateObjectKey(key); err != nil {
		return fail("quarantined", err)
	}
	// file_url намеренно игнорируется; скомпрометированная строка не должна запускать внутренний HTTP-запрос.
	// Источники читаются из локального корня либо заранее настроенного S3.
	body, err := r.Source.Open(ctx, key)
	if err != nil {
		return fail("quarantined", fmt.Errorf("Исходный объект отсутствует или повреждён: %w", err))
	}
	payload, readErr := io.ReadAll(io.LimitReader(body, texturepng.MaxEncodedBytes+1))
	closeErr := body.Close()
	if readErr != nil {
		return fail("quarantined", readErr)
	}
	if closeErr != nil {
		return fail("quarantined", closeErr)
	}
	if len(payload) > texturepng.MaxEncodedBytes {
		return fail("quarantined", errors.New("Исходное изображение превышает 4 МиБ"))
	}
	if err = VerifySourceHash(hash, payload); err != nil {
		return fail("quarantined", err)
	}
	processed, err := texturepng.Process(bytes.NewReader(payload), rec.Kind, modelName)
	if err != nil {
		return fail("quarantined", fmt.Errorf("Некорректное значение: PNG: %w", err))
	}
	rec.NormalizedDigest = processed.Digest
	if r.DryRun {
		rec.Status = "validated-dry-run"
		return rec
	}
	expectedKey := "texture-blobs/sha256/" + processed.Digest[:2] + "/" + processed.Digest + ".png"
	input := repository.VerifiedTexture0252{Digest: processed.Digest, Width: processed.Width, Height: processed.Height, Size: int64(len(processed.PNG)), Driver: r.Destination.Driver(), ObjectKey: expectedKey,
		Kind: rec.Kind, Model: modelName, Visibility: "public", Source: "managed-gravit-import", ExpectedRevision: rev, GravitSourceID: r.SourceID, GravitRowID: row.ID, GravitExternalUUID: normalizedUUID, GravitOriginalHash: hash}
	if err = r.Database.StageTextureUpload0253(ctx, profile, input); err != nil {
		return fail("blocked", err)
	}
	savedKey, n, err := storage.PutTextureImmutable0253(ctx, r.Destination, processed.Digest, processed.PNG)
	if err != nil {
		return fail("blocked", err)
	}
	if savedKey != expectedKey || n != input.Size {
		return fail("blocked", errors.New("Ошибка: «storage key/size verification»"))
	}
	_, err = r.Database.UploadTexture0252(ctx, profile, input)
	if errors.Is(err, repository.ErrGravitAlreadyImported02510) {
		rec.Status = "already-imported"
		return rec
	}
	if err != nil {
		return fail("blocked", err)
	}
	rec.Status = "imported"
	return rec
}

// LocalSource следует недоверенным URL. Файлы должны разрешаться внутри настроенного корневого каталога
// оператора; выходящие за его пределы символические ссылки отклоняются.
type LocalSource struct{ Root string }

func (s LocalSource) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := ValidateObjectKey(key); err != nil {
		return nil, err
	}
	root, err := filepath.EvalSymlinks(s.Root)
	if err != nil {
		return nil, err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	p, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(key)))
	if err != nil {
		return nil, err
	}
	relative, err := filepath.Rel(root, p)
	if err != nil {
		return nil, err
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("Исходный объект выходит за пределы локального корневого каталога")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	stat, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !stat.Mode().IsRegular() || stat.Size() > texturepng.MaxEncodedBytes {
		f.Close()
		return nil, errors.New("Файл PNG не является обычным файлом допустимого размера")
	}
	return f, nil
}
