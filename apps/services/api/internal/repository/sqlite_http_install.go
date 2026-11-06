package repository

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

const sqliteInstallationDDL0375 = `CREATE TABLE IF NOT EXISTS http_installation_0375 (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 token_hash TEXT NOT NULL,
 token_used_at INTEGER,
 completed_at INTEGER,
 CHECK(completed_at IS NULL OR token_used_at IS NOT NULL)
)`

func minimalTokenDigest0375(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

// InitializeMinimalInstallation0375 сохраняет проверяющий bootstrap-секрет до запуска
// слушателя. Существующий проверяющий нельзя заменить перенастройкой окружения.
func (r *SQLiteHTTPRepository0372) InitializeMinimalInstallation0375(ctx context.Context, token string, require bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed != nil {
		return r.failed
	}
	token = strings.TrimSpace(token)
	return r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		if _, e := q.ExecContext(ctx, sqliteInstallationDDL0375); e != nil {
			return e
		}
		if _, e := q.ExecContext(ctx, `INSERT OR IGNORE INTO http_installation_0375(singleton,token_hash) VALUES(1,'')`); e != nil {
			return e
		}
		var hash string
		var used, complete sql.NullInt64
		if e := q.QueryRowContext(ctx, `SELECT token_hash,token_used_at,completed_at FROM http_installation_0375 WHERE singleton=1`).Scan(&hash, &used, &complete); e != nil {
			return e
		}
		if hash == "" && !used.Valid && !complete.Valid {
			if len(r.mem.users) > 0 {
				return errors.New("Требуется: в SQLite уже есть пользователи без состояния установки; требуется восстановление вручную")
			}
			if token == "" {
				if require {
					return errors.New("для новой промышленной установки SQLite требуется «токен первоначальной настройки»")
				}
				return nil
			}
			if len(token) < 32 {
				return errors.New("Токен первоначальной настройки должен содержать не менее 32 символов")
			}
			_, e := q.ExecContext(ctx, `UPDATE http_installation_0375 SET token_hash=? WHERE singleton=1 AND token_hash=''`, minimalTokenDigest0375(token))
			return e
		}
		if !used.Valid && !complete.Valid && token != "" && subtle.ConstantTimeCompare([]byte(hash), []byte(minimalTokenDigest0375(token))) != 1 {
			return errors.New("Токен первоначальной настройки не соответствует инициализированной установке")
		}
		return nil
	})
}

func (r *SQLiteHTTPRepository0372) MinimalInstallationStatus0375(ctx context.Context) (string, bool, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed != nil {
		return "", false, false, r.failed
	}
	var hash string
	var used, completed sql.NullInt64
	err := r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		return q.QueryRowContext(ctx, `SELECT token_hash,token_used_at,completed_at FROM http_installation_0375 WHERE singleton=1`).Scan(&hash, &used, &completed)
	})
	return hash, used.Valid, completed.Valid, err
}

// BootstrapMinimalAdmin0375 связывает использование токена, владельца и идентичность,
// аудит и снимок HTTP-домена ровно в одной WAL-транзакции. До фиксации ни один запрос
// не видит владельца. Неизвестный результат фиксации делает репозиторий непригодным.
func (r *SQLiteHTTPRepository0372) BootstrapMinimalAdmin0375(ctx context.Context, user model.User, identity model.AuthIdentity, token, actor string) (model.User, error) {
	r.mu.Lock()
	start := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(start)
	if r.failed != nil {
		return model.User{}, r.failed
	}
	if len(r.mem.users) != 0 {
		return model.User{}, errors.New("Первый администратор уже создан")
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return model.User{}, errors.New("Требуется: токен начальной загрузки")
	}
	// Проверяйте токен до изменения кэша. Повторяйте проверку внутри
	// WRITE-транзакции, исключая гонку с будущим отдельным потребителем.
	var stored string
	var used, completed sql.NullInt64
	if err := r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		return q.QueryRowContext(ctx, `SELECT token_hash,token_used_at,completed_at FROM http_installation_0375 WHERE singleton=1`).Scan(&stored, &used, &completed)
	}); err != nil {
		return model.User{}, err
	}
	if stored == "" || used.Valid || completed.Valid || subtle.ConstantTimeCompare([]byte(stored), []byte(minimalTokenDigest0375(token))) != 1 {
		return model.User{}, errors.New("некорректный или уже использованный токен первоначальной настройки")
	}
	created, err := r.mem.SaveUser(user)
	if err != nil {
		return model.User{}, err
	}
	identity.UserID = created.ID
	if _, err = r.mem.SaveAuthIdentity(identity); err != nil {
		r.failed = err
		return model.User{}, err
	}
	now := time.Now().UTC()
	r.mem.audit = append(r.mem.audit, model.AuditEvent{ID: fmt.Sprintf("install-admin-%d", now.UnixNano()), Actor: actor, Action: "install.bootstrap-admin", Target: created.Email, UserAgent: "0.37.5", CreatedAt: now})
	raw, err := json.Marshal(snapshotSQLiteHTTP0372(r.mem))
	if err != nil {
		r.failed = err
		return model.User{}, err
	}
	sum := sha256.Sum256(raw)
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		result, e := q.ExecContext(ctx, `UPDATE http_installation_0375 SET token_used_at=? WHERE singleton=1 AND token_hash=? AND token_used_at IS NULL AND completed_at IS NULL`, now.Unix(), stored)
		if e != nil {
			return e
		}
		n, e := result.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrConflict
		}
		result, e = q.ExecContext(ctx, `UPDATE http_repository_state_0372 SET sequence=sequence+1,sha256=?,document=? WHERE singleton=1 AND sequence=?`, hex.EncodeToString(sum[:]), raw, r.seq)
		if e != nil {
			return e
		}
		n, e = result.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		r.failed = fmt.Errorf("Атомарная фиксация первоначальной настройки: %w", err)
		return model.User{}, r.failed
	}
	r.seq++
	r.digest = hex.EncodeToString(sum[:])
	return created, nil
}

func (r *SQLiteHTTPRepository0372) CompleteMinimalInstallation0375(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed != nil {
		return r.failed
	}
	if len(r.mem.users) == 0 || len(r.mem.projects) == 0 {
		return errors.New("для завершения установки требуются администратор и проект")
	}
	return r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		var used, completed sql.NullInt64
		if e := q.QueryRowContext(ctx, `SELECT token_used_at,completed_at FROM http_installation_0375 WHERE singleton=1`).Scan(&used, &completed); e != nil {
			return e
		}
		if completed.Valid {
			return nil
		}
		if !used.Valid {
			return errors.New("администратор первоначальной настройки должен быть создан до завершения установки")
		}
		res, e := q.ExecContext(ctx, `UPDATE http_installation_0375 SET completed_at=?,token_hash='' WHERE singleton=1 AND token_used_at IS NOT NULL AND completed_at IS NULL`, time.Now().UTC().Unix())
		if e != nil {
			return e
		}
		n, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrConflict
		}
		return nil
	})
}
