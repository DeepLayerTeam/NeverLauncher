package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/fileauth"
	gc "gitflic.ru/skif4er/launcher/services/api/internal/gravitcredentials"
	gi "gitflic.ru/skif4er/launcher/services/api/internal/gravitidentity"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
)

func migratedUserID0335(a gi.Account) string {
	if a.Provider == "fileauth" {
		return "gravit-fileauth-" + strings.ReplaceAll(a.UUID, "-", "")
	}
	// SQL ID источника локальны для внешней БД и часто начинаются с 1. Разные
	// проекты не должны претендовать на одного пользователя Never по исходному
	// ID. Межсерверная идентичность, которую мы сохраняем, — Minecraft UUID.
	return "gravit-sql-" + strings.ReplaceAll(a.UUID, "-", "")
}

// Используется ТОЛЬКО для проверки квитанций 0.44.3: старые импорты индексировали
// SQL-пользователей лишь по ID внешней строки. Новые импорты никогда не должны
// применять эту схему с коллизиями.
func legacyMigratedSQLUserID0335(a gi.Account) string {
	sum := sha256.Sum256([]byte("sql\x00" + a.SourceID))
	return "gravit-sql-" + hex.EncodeToString(sum[:16])
}

// ImportMigrationCredentials0335 атомарно создаёт только новых локальных
// пользователей и сохраняет неизменяемый Minecraft UUID. Существующих
// пользователей Never НИКОГДА не перезаписывают, объединяют, наделяют правами или
// незаметно снабжают хешами источника. Пробный запуск применяет те же проверки
// коллизий без изменений БД.
func (r *SQLRepository) ImportMigrationCredentials0335(ctx context.Context, id, source, format string, credentials []gc.Credential, dryRun bool) (gc.Result, error) {
	if e := r.check(); e != nil {
		return gc.Result{}, e
	}
	if len(credentials) == 0 || len(credentials) > gi.MaxAccounts {
		return gc.Result{}, errors.New("Набор учётных данных пуст или превышает допустимый размер")
	}
	tx, e := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if e != nil {
		return gc.Result{}, e
	}
	defer tx.Rollback()
	// Используйте ту же блокировку импортёра, чтобы не допустить параллельных массовых
	// импортов FileAuth.
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(2945,1)`); e != nil {
		return gc.Result{}, e
	}
	var runStatus, runStep, runKind string
	e = tx.QueryRowContext(ctx, `SELECT status,step,source_kind FROM migration_runs_0331 WHERE id=$1 FOR UPDATE`, id).Scan(&runStatus, &runStep, &runKind)
	if errors.Is(e, sql.ErrNoRows) {
		return gc.Result{}, mw.ErrNotFound
	}
	if e != nil {
		return gc.Result{}, e
	}
	if runStatus != "prepared" || runStep != "source_assessment" || runKind != "gravit" {
		return gc.Result{}, mw.ErrBusy
	}
	var savedSource, savedIdentity, inventorySHA string
	e = tx.QueryRowContext(ctx, `SELECT s.source_sha256,s.entries_sha256,s.inventory_sha256 FROM migration_identity_snapshots_0334 s WHERE s.run_id=$1`, id).Scan(&savedSource, &savedIdentity, &inventorySHA)
	if errors.Is(e, sql.ErrNoRows) {
		return gc.Result{}, mw.ErrConflict
	}
	if e != nil {
		return gc.Result{}, e
	}
	if source != savedSource {
		return gc.Result{}, mw.ErrConflict
	}
	var invSource, invManifest string
	e = tx.QueryRowContext(ctx, `SELECT source_sha256,manifest_sha256 FROM migration_source_inventory_0333 WHERE run_id=$1`, id).Scan(&invSource, &invManifest)
	if e != nil {
		return gc.Result{}, e
	}
	if invSource != source || invManifest != inventorySHA {
		return gc.Result{}, mw.ErrConflict
	}
	fingerprint := gc.SourceFingerprint(source, savedIdentity, format)
	var oldFingerprint string
	var oldRaw []byte
	e = tx.QueryRowContext(ctx, `SELECT decision_sha256,report FROM migration_auth_imports_0335 WHERE run_id=$1`, id).Scan(&oldFingerprint, &oldRaw)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return gc.Result{}, e
	}
	if e == nil {
		if fingerprint != oldFingerprint {
			return gc.Result{}, mw.ErrConflict
		}
		var old gc.Result
		if e = json.Unmarshal(oldRaw, &old); e != nil {
			return gc.Result{}, e
		}
		// Проверяйте созданные аккаунты перед сообщением об успехе повтора. Пароли могли
		// законно обновиться после входа и не сравниваются.
		for _, row := range old.Rows {
			if row.State != "imported" {
				continue
			}
			a := gi.Account{Provider: row.Provider, SourceID: row.SourceID, Username: row.Username, UUID: row.UUID}
			var uuid, name, role, status, email string
			userID := migratedUserID0335(a)
			e = tx.QueryRowContext(ctx, `SELECT m.uuid,m.name,u.role_id,u.status,u.email FROM users u JOIN minecraft_profiles m ON m.user_id=u.id WHERE u.id=$1`, userID).Scan(&uuid, &name, &role, &status, &email)
			if errors.Is(e, sql.ErrNoRows) && a.Provider == "sql" {
				// Проверенные исторические квитанции ещё могут ссылаться на пользователя
				// 0.44.3 с привязкой к исходному ID. Перед повтором проверяйте владение.
				e = tx.QueryRowContext(ctx, `SELECT m.uuid,m.name,u.role_id,u.status,u.email FROM users u JOIN minecraft_profiles m ON m.user_id=u.id WHERE u.id=$1`, legacyMigratedSQLUserID0335(a)).Scan(&uuid, &name, &role, &status, &email)
			}
			if e != nil || uuid != a.UUID || name != a.Username || role != "player" || status != "active" || email != strings.ToLower(a.Username)+"@fileauth.invalid" {
				return gc.Result{}, mw.ErrConflict
			}
		}
		old.DryRun = dryRun
		return old, nil
	}
	mapped, e := migrationIdentityRows0334(ctx, tx, id)
	if e != nil {
		return gc.Result{}, e
	}
	if len(mapped) != len(credentials) {
		return gc.Result{}, mw.ErrConflict
	}
	digest, e := gi.Digest(mapped)
	if e != nil {
		return gc.Result{}, e
	}
	if digest != savedIdentity {
		return gc.Result{}, mw.ErrConflict
	}
	byKey := map[string]gc.Credential{}
	for _, c := range credentials {
		k := c.Provider + "\x00" + c.SourceID + "\x00" + c.SourcePath
		if _, ok := byKey[k]; ok {
			return gc.Result{}, mw.ErrConflict
		}
		byKey[k] = c
	}
	targets, e := migrationIdentityTargets0334(ctx, tx)
	if e != nil {
		return gc.Result{}, e
	}
	// Сопоставьте РАНЕЕ ОДОБРЕННОЕ владение с действующей таблицей учётных записей:
	// UUID, занятый после MIG04, не является утверждённой связью.
	savedRows, e := tx.QueryContext(ctx, `SELECT status,COALESCE(target_user_id,'') FROM migration_identity_rows_0334 WHERE run_id=$1 ORDER BY ordinal`, id)
	if e != nil {
		return gc.Result{}, e
	}
	type approval struct{ status, user string }
	approved := []approval{}
	for savedRows.Next() {
		var a approval
		if e = savedRows.Scan(&a.status, &a.user); e != nil {
			savedRows.Close()
			return gc.Result{}, e
		}
		approved = append(approved, a)
	}
	e = savedRows.Err()
	savedRows.Close()
	if e != nil {
		return gc.Result{}, e
	}
	if len(approved) != len(mapped) {
		return gc.Result{}, mw.ErrConflict
	}
	resolved, _ := gi.Reconcile(mapped, targets)
	result := gc.Result{Format: gc.Format, RunID: id, SourceSHA256: source, IdentitySHA256: savedIdentity, Rows: make([]gc.Row, 0, len(mapped)), DryRun: dryRun}
	for i, a := range mapped {
		k := a.Provider + "\x00" + a.SourceID + "\x00" + a.SourcePath
		c, ok := byKey[k]
		if !ok || c.Username != a.Username || c.UUID != a.UUID || (c.State != "importable" && c.State != "manual_reset") || (c.State == "manual_reset" && c.PasswordHash != "") {
			return gc.Result{}, mw.ErrConflict
		}
		m := resolved[i]
		// Ранее заблокированная или сопоставленная идентичность не должна незаметно
		// становиться кандидатом на импорт из-за удаления или изменения конфликтующей
		// цели другим оператором. Нужна новая проверка MIG04.
		if approved[i].status != m.Status || approved[i].user != m.TargetUserID {
			return gc.Result{}, fmt.Errorf("Владелец UUID изменился после утверждения сопоставления для %s: %w", a.SourceID, mw.ErrConflict)
		}
		if m.Status == "blocked" {
			return gc.Result{}, fmt.Errorf("Сопоставление UUID для %s заблокировано: %w", a.SourceID, mw.ErrConflict)
		}
		row := gc.Row{Provider: a.Provider, SourceID: a.SourceID, Username: a.Username, UUID: a.UUID}
		if m.Status == "matched" {
			// Текущие локальные учётные данные аккаунта принадлежат Never. Никогда не
			// заменяйте их.
			row.State = "existing_unchanged"
			row.Reason = "Never identity already exists; source password not installed; operator must verify login"
			result.ExistingUnchanged++
		} else if c.State != "importable" {
			row.State = "manual_reset"
			row.Reason = c.Reason
			result.ManualReset++
		} else {
			if c.PasswordHash == "" {
				return gc.Result{}, errors.New("Для импортируемых учётных данных отсутствует средство проверки")
			}
			if strings.HasPrefix(c.PasswordHash, "$argon2id$") {
				if c.Algorithm != "argon2id" || !fileauth.ValidateArgon2id(c.PasswordHash) {
					return gc.Result{}, mw.ErrConflict
				}
			} else {
				algorithm, _, ok := fileauth.DecodeCredential(c.PasswordHash)
				if !ok || (algorithm != c.Algorithm && !(algorithm == "sha256-hex" && c.Algorithm == "sha256-base64url")) {
					return gc.Result{}, mw.ErrConflict
				}
			}
			userID := migratedUserID0335(a)
			email := strings.ToLower(a.Username) + "@fileauth.invalid"
			var conflict bool
			e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 OR lower(email)=$2)`, userID, email).Scan(&conflict)
			if e != nil {
				return gc.Result{}, e
			}
			if conflict {
				return gc.Result{}, fmt.Errorf("Пользователь или адрес почты уже зарезервирован для %s: %w", a.Username, mw.ErrConflict)
			}
			if !dryRun {
				_, e = tx.ExecContext(ctx, `INSERT INTO users(id,email,display_name,role_id,status,project_roles,password_hash,password_updated_at,created_at,updated_at)
       VALUES($1,$2,$3,'player','active','{}'::jsonb,$4,now(),now(),now())`, userID, email, a.Username, c.PasswordHash)
				if e != nil {
					return gc.Result{}, e
				}
				_, e = tx.ExecContext(ctx, `INSERT INTO auth_identities(id,user_id,provider,issuer,subject,email,username,display_name,claims,created_at,updated_at)
       VALUES($1,$2,'local','launcher',$2,$3,$4,$4,'{}'::jsonb,now(),now())`, "identity-local-"+userID, userID, email, a.Username)
				if e != nil {
					return gc.Result{}, e
				}
				_, e = tx.ExecContext(ctx, `INSERT INTO minecraft_profiles(user_id,uuid,name,issuer,realm,subject,identity_version,created_at,updated_at)
       VALUES($1,$2,$3,'launcher','local',$2,'gravit-import-v1',now(),now())`, userID, a.UUID, a.Username)
				if e != nil {
					return gc.Result{}, e
				}
			}
			row.State = "imported"
			result.Imported++
		}
		result.Rows = append(result.Rows, row)
	}
	result.Complete = result.ManualReset == 0 && result.ExistingUnchanged == 0
	if dryRun {
		return result, nil
	}
	raw, e := json.Marshal(result)
	if e != nil {
		return gc.Result{}, e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO migration_auth_imports_0335(run_id,source_sha256,identity_sha256,decision_sha256,report) VALUES($1,$2,$3,$4,$5::jsonb)`, id, source, savedIdentity, fingerprint, string(raw))
	if e != nil {
		return gc.Result{}, e
	}
	var revision int64
	e = tx.QueryRowContext(ctx, `UPDATE migration_runs_0331 SET revision=revision+1,updated_at=now() WHERE id=$1 RETURNING revision`, id).Scan(&revision)
	if e != nil {
		return gc.Result{}, e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO migration_events_0331(run_id,kind,step,revision,detail) VALUES($1,'gravit_auth_imported','source_assessment',$2,jsonb_build_object('imported',$3::int,'manualReset',$4::int,'existingUnchanged',$5::int))`, id, revision, result.Imported, result.ManualReset, result.ExistingUnchanged)
	if e != nil {
		return gc.Result{}, e
	}
	if e = tx.Commit(); e != nil {
		return gc.Result{}, fmt.Errorf("Фиксация импорта авторизации не подтверждена; повторите с тем же источником: %w", e)
	}
	return result, nil
}

func (r *SQLRepository) GetMigrationCredentials0335(ctx context.Context, id string) (gc.Result, error) {
	if e := r.check(); e != nil {
		return gc.Result{}, e
	}
	var data []byte
	e := r.db.QueryRowContext(ctx, `SELECT report FROM migration_auth_imports_0335 WHERE run_id=$1`, id).Scan(&data)
	if errors.Is(e, sql.ErrNoRows) {
		return gc.Result{}, mw.ErrNotFound
	}
	if e != nil {
		return gc.Result{}, e
	}
	var out gc.Result
	e = json.Unmarshal(data, &out)
	return out, e
}
