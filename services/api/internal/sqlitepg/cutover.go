package sqlitepg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// CutoverCheck0475 проверяет зафиксированные импорты, реальный SQLRepository reader
// и квитанцию целевого файла. Он не разрешает переключать Backend: HTTP,
// Coordinator и внешнее состояние Runtime требуют независимой сверки.
// Эта проверка не выполняет SQL-запросы к исходной базе SQLite.
type CutoverCheck0475 struct {
	SourceSHA256           string `json:"sourceSha256"`
	LiveVerified           bool   `json:"liveVerified"`
	FilesVerified          bool   `json:"filesVerified"`
	RepositoryVerified     bool   `json:"repositoryVerified"`
	ProjectID              string `json:"projectId"`
	OwnerID                string `json:"ownerId"`
	FileObjects            int64  `json:"fileObjects"`
	CheckedTables          int    `json:"checkedTables"`
	ReadyForBackendCutover bool   `json:"readyForBackendCutover"`
}

func VerifyCutover0475(ctx context.Context, dsn, sourceSHA, projectID, ownerEmail string) (CutoverCheck0475, error) {
	result := CutoverCheck0475{SourceSHA256: sourceSHA, ProjectID: projectID}
	if len(sourceSHA) != 64 || strings.ToLower(sourceSHA) != sourceSHA || strings.TrimSpace(dsn) == "" || projectID == "" || ownerEmail == "" {
		return result, errors.New("Требуется: «source SHA-256, PostgreSQL DSN, project ID and owner email are»")
	}
	if _, err := hex.DecodeString(sourceSHA); err != nil {
		return result, err
	}
	pg, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return result, fmt.Errorf("Не удалось подключиться к PostgreSQL (учётные данные скрыты): %w", err)
	}
	defer pg.Close(context.Background())
	// Квитанция и счётчики должны относиться к одному снимку БД. Получить
	// снимок repeatable-read без записи и зависимости от готовности HTTP.
	tx, err := pg.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer tx.Rollback(context.Background())
	var raw string
	if err = tx.QueryRow(ctx, `SELECT report::text FROM sqlite_live_receipts_0473 WHERE source_sha256=$1`, sourceSHA).Scan(&raw); err != nil {
		return result, fmt.Errorf("Не найдено: «matching live import receipt»: %w", err)
	}
	var report LiveReport0473
	if err = json.Unmarshal([]byte(raw), &report); err != nil {
		return result, err
	}
	if report.Format != liveImportVersion0473 || !report.Verified || report.SourceSHA256 != sourceSHA || report.StateVersion != stateVersion0474 || report.ReadyForBackendCutover || len(report.LiveTables) != len(rules0473())+len(stateRules0474()) {
		return result, errors.New("unverified or inconsistent live import receipt")
	}
	allowed := make(map[string]string)
	for _, rule := range rules0473() {
		allowed[rule.source] = rule.target
	}
	for _, rule := range stateRules0474() {
		allowed[rule.source] = rule.target
	}
	seen := make(map[string]bool)
	for _, table := range report.LiveTables {
		if allowed[table.Source] != table.Destination || seen[table.Source] || table.Rows < 0 {
			return result, errors.New("Некорректное значение: «live table receipt»")
		}
		seen[table.Source] = true
		// Имя таблицы берётся только из скомпилированных сопоставлений, а не из JSON-квитанции.
		var count int64
		query := `SELECT count(*) FROM ` + quoted(table.Destination)
		if table.Source == "bridge_runtime" {
			query += ` WHERE core_runtime_status_0474<>''`
		}
		if table.Source == "auth_revocation_events" {
			query += ` WHERE event_type='sqlite-session-revocation'`
		}
		if err = tx.QueryRow(ctx, query).Scan(&count); err != nil {
			return result, fmt.Errorf("%s: %w", table.Destination, err)
		}
		if count != table.Rows {
			return result, fmt.Errorf("%s changed since import: %d != %d", table.Destination, count, table.Rows)
		}
	}
	result.CheckedTables = len(seen)
	result.LiveVerified = true
	var driver, catalogDigest string
	var count int64
	if err = tx.QueryRow(ctx, `SELECT driver,objects,catalog_sha256 FROM sqlite_file_receipts_0474 WHERE source_sha256=$1`, sourceSHA).Scan(&driver, &count, &catalogDigest); err != nil {
		return result, fmt.Errorf("Отсутствует: «matching verified file-copy receipt»: %w", err)
	}
	if count != report.Files || (driver != "local" && driver != "s3") {
		return result, errors.New("file receipt inconsistent with live import")
	}
	var actual int64
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM files`).Scan(&actual); err != nil {
		return result, err
	}
	if actual != count {
		return result, errors.New("files catalog modified since verified file copy")
	}
	// Квитанция 0.47.4 только со счётчиками не доказывает идентичность каталога. Запросить
	// полный канонический набор строк и сравнить с квитанцией копирования файлов.
	rows, err := tx.Query(ctx, `SELECT project_id,version_id,path,size,sha256 FROM files ORDER BY project_id,version_id,path`)
	if err != nil {
		return result, err
	}
	objects := make([]fileObject0474, 0)
	for rows.Next() {
		var object fileObject0474
		if err = rows.Scan(&object.project, &object.version, &object.path, &object.size, &object.hash); err != nil {
			break
		}
		objects = append(objects, object)
	}
	scanErr := rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	if scanErr != nil {
		return result, scanErr
	}
	bytes, err := json.Marshal(objects)
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(bytes)
	if catalogDigest == "" || catalogDigest != hex.EncodeToString(digest[:]) {
		return result, errors.New("file catalog fingerprint mismatches verified copy; rerun offline copy")
	}
	result.FilesVerified = true
	result.FileObjects = count
	// Убедиться, что указанный предыдущий владелец сохранил ту же идентичность,
	// пароль, активный статус и разрешения проекта. Читать из
	// той же транзакции; SQLRepository проверяется отдельно ниже.
	var ownerID, role, password, status string
	if err = tx.QueryRow(ctx, `SELECT id,role_id,password_hash,status FROM users WHERE lower(email)=lower($1)`, ownerEmail).Scan(&ownerID, &role, &password, &status); err != nil {
		return result, fmt.Errorf("Не найдено: владелец: %w", err)
	}
	if password == "" || status != "active" {
		return result, errors.New("владелец: запрещено «authenticate using imported password»")
	}
	var belongs bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1)`, projectID).Scan(&belongs); err != nil || !belongs {
		return result, errors.New("imported project absent")
	}
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM project_user_roles WHERE user_id=$1 AND project_id=$2)`, ownerID, projectID).Scan(&belongs); err != nil {
		return result, err
	}
	if !belongs && role != "owner" && role != "admin" {
		return result, errors.New("owner has no project access")
	}
	result.OwnerID = ownerID
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	// Проверять те же сохранённые объекты через настоящую реализацию Backend-репозитория,
	// а не через реконструированное промежуточное представление.
	r := repository.NewSQLRepository("pgx", dsn, "")
	defer func() {
		if c, ok := r.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	}()
	if err = r.(interface{ Health(context.Context) error }).Health(ctx); err != nil {
		return result, err
	}
	owner, err := r.GetUserByEmail(ownerEmail)
	if err != nil || owner.ID != ownerID || owner.PasswordHash == "" || owner.Status != "active" {
		return result, errors.New("SQLRepository failed to read migrated owner")
	}
	project, err := r.GetProject(projectID)
	if err != nil || project.ID != projectID {
		return result, errors.New("SQLRepository failed to read migrated project")
	}
	if _, err = r.ListProfiles(projectID); err != nil {
		return result, fmt.Errorf("SQLRepository failed to list profiles: %w", err)
	}
	result.RepositoryVerified = true
	// НИКАКОГО автоматического одобрения. Версия 0.47.4 не переносит HTTP/Coordinator и т. п.
	result.ReadyForBackendCutover = false
	return result, nil
}
