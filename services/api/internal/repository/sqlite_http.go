package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

// SQLiteHTTPRepository0372 сохраняет полное доменное состояние HTTP-репозитория
// в однопроцессной базе SQLite с WAL и FULL-sync. Доменная модель в памяти —
// кэш, а не постоянный источник: изменение возвращается только после того, как
// новое состояние и его дайджест целостности зафиксированы атомарно. Подход предназначен
// для небольшой одноузловой установки, но не для сетевого HA и больших объёмов данных.
//
// Публикация stable использует проверку подписанной аттестации с привязкой к SQLite и одноразовые транзакционные
// допуски 0.37.4; минимальное развёртывание 0.37.5 поддерживает один локальный экземпляр Linux. Онлайн-бэкапы и
// двусторонняя миграция остаются отдельными этапами.
type SQLiteHTTPRepository0372 struct {
	mu        sync.Mutex
	store     *sqlitedurable.Store
	mem       *MemoryRepository
	seq       int64
	digest    string
	failed    error
	auditSink func(model.AuditEvent)
}

var _ Repository = (*SQLiteHTTPRepository0372)(nil)

const sqliteHTTPDDL0372 = `CREATE TABLE IF NOT EXISTS http_repository_state_0372 (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    state_version INTEGER NOT NULL CHECK(state_version=1),
    sequence INTEGER NOT NULL CHECK(sequence>=1),
    sha256 TEXT NOT NULL,
    document BLOB NOT NULL
)`

// OpenSQLiteHTTPRepository0372 владеет базой и отклоняет другой процесс,
// пытающийся открыть тот же файл SQLite. Резервного переключения на память нет.
func OpenSQLiteHTTPRepository0372(ctx context.Context, path, publicURL string) (_ *SQLiteHTTPRepository0372, err error) {
	store, err := sqlitedurable.Open(ctx, sqlitedurable.Options{Path: path})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = store.Close()
		}
	}()
	r := &SQLiteHTTPRepository0372{store: store, mem: NewMemoryRepository(publicURL)}
	// Заполняет производственный HTTP-репозиторий демонстрационными данными разработки,
	// учётные данные администратора по умолчанию или заранее опубликованный синтетический выпуск.
	r.mem.projects = nil
	r.mem.profiles = nil
	r.mem.channels = nil
	r.mem.releases = nil
	r.mem.files = nil
	r.mem.users = nil
	r.mem.identities = nil
	r.mem.audit = nil
	r.mem.channelHeads = make(map[string]model.ChannelHead)
	r.mem.validationPolicies = make(map[string]model.ProjectValidationPolicy)
	// Никогда не инициализируйте постороннюю или непустую SQLite-БД как новую
	// установку. Отсутствующий снимок в существующей БД — повреждение, а не
	// разрешение незаметно стереть проект.
	existing := false
	err = store.Read(ctx, func(q sqlitedurable.Executor) error {
		rows, e := q.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			if e = rows.Scan(&name); e != nil {
				return e
			}
			if name != "http_repository_state_0372" { // другим таблицам требуется таблица состояний в качестве владельца
				existing = true
				continue
			}
			existing = true
		}
		if e = rows.Err(); e != nil {
			return e
		}
		if !existing {
			return nil
		}
		var found int
		if e = q.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='http_repository_state_0372'`).Scan(&found); e != nil {
			return e
		}
		if found != 1 {
			return errors.New("В существующей базе отсутствует таблица состояния SQLite HTTP")
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("Предварительная проверка SQLite HTTP: %w", err)
	}
	legacy, upgraded, e := preflightHTTPUpgrade0472(ctx, store, existing)
	if e != nil {
		return nil, fmt.Errorf("Предварительная проверка совместимости SQLite HTTP: %w", e)
	}
	if legacy {
		if _, e = sqlitedurable.PreUpgradeBackup0472(ctx, path, "http-v1-upgrade"); e != nil {
			return nil, e
		}
		if e = migrateHTTPSnapshot0472(ctx, store, upgraded); e != nil {
			return nil, fmt.Errorf("Обновление SQLite HTTP: %w", e)
		}
	}
	err = store.Write(ctx, func(q sqlitedurable.Executor) error {
		_, e := q.ExecContext(ctx, sqliteHTTPDDL0372)
		if e != nil {
			return e
		}
		_, e = q.ExecContext(ctx, sqliteRuntimeDDL0373)
		if e != nil {
			return e
		}
		for _, stmt := range strings.Split(sqliteStablePermitDDL0374, ";") {
			if strings.TrimSpace(stmt) == "" {
				continue
			}
			if _, e = q.ExecContext(ctx, stmt); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("Схема SQLite HTTP: %w", err)
	}
	var raw []byte
	var sha string
	var ver int
	err = store.Read(ctx, func(q sqlitedurable.Executor) error {
		return q.QueryRowContext(ctx, `SELECT state_version,sequence,sha256,document FROM http_repository_state_0372 WHERE singleton=1`).Scan(&ver, &r.seq, &sha, &raw)
	})
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if existing {
			return nil, errors.New("В существующей базе отсутствует снимок SQLite HTTP; инициализация пустого состояния запрещена")
		}
		err = r.persist(ctx)
		if err != nil {
			return nil, fmt.Errorf("Создание: SQLite HTTP состояние: %w", err)
		}
	case err != nil:
		return nil, fmt.Errorf("Чтение: SQLite HTTP состояние: %w", err)
	case ver != 1:
		return nil, fmt.Errorf("Неподдерживаемый формат состояния SQLite HTTP: %d", ver)
	case r.seq < 1:
		return nil, errors.New("Некорректный номер последовательности SQLite HTTP")
	default:
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != sha {
			return nil, errors.New("Не совпадает контрольная сумма целостности состояния SQLite HTTP")
		}
		state, e := decodeSQLiteHTTPDocument0471(raw)
		if e != nil {
			return nil, fmt.Errorf("Повреждено состояние SQLite HTTP: %w", e)
		}
		r.digest = sha
		restoreSQLiteHTTP0372(r.mem, state)
	}
	return r, nil
}

// persist вызывается с удерживаемой блокировкой операции репозитория, кроме
// начального Open. Ошибка фиксации делает экземпляр непригодным, чтобы
// незафиксированный кэш процесса никогда не выдавался за устойчивое состояние.
func (r *SQLiteHTTPRepository0372) persist(ctx context.Context) error {
	raw, err := json.Marshal(snapshotSQLiteHTTP0372(r.mem))
	if err != nil {
		return fmt.Errorf("Сериализация состояния SQLite HTTP: %w", err)
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		if r.seq == 0 {
			_, e := q.ExecContext(ctx, `INSERT INTO http_repository_state_0372(singleton,state_version,sequence,sha256,document) VALUES (1,1,1,?,?)`, digest, raw)
			return e
		}
		result, e := q.ExecContext(ctx, `UPDATE http_repository_state_0372 SET sequence=sequence+1,sha256=?,document=? WHERE singleton=1 AND sequence=? AND state_version=1`, digest, raw, r.seq)
		if e != nil {
			return e
		}
		changed, e := result.RowsAffected()
		if e != nil {
			return e
		}
		if changed != 1 {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("Фиксация: SQLite HTTP состояние: %w", err)
	}
	r.seq++
	r.digest = digest
	return nil
}

// decodeSQLiteHTTPDocument0471 проверяет сохранённую оболочку без потери
// неизвестных или отсутствующих полей. Одного encoding/json.Unmarshal
// недостаточно: иначе JSON несовместимой версии может загрузиться как пустые
// коллекции, хотя контрольная сумма документа верна.
func decodeSQLiteHTTPDocument0471(raw []byte) (sqliteHTTPState0372, error) {
	var state sqliteHTTPState0372
	expected := make(map[string]struct{})
	typ := reflect.TypeOf(state)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			return state, fmt.Errorf("Поле снимка SQLite без версии: %s", field.Name)
		}
		expected[name] = struct{}{}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	tok, err := decoder.Token()
	if err != nil {
		return state, err
	}
	if tok != json.Delim('{') {
		return state, errors.New("Снимок SQLite HTTP должен быть объектом")
	}
	seen := make(map[string]struct{}, len(expected))
	for decoder.More() {
		tok, err = decoder.Token()
		if err != nil {
			return state, err
		}
		name, ok := tok.(string)
		if !ok {
			return state, errors.New("Свойство снимка SQLite HTTP не является строкой")
		}
		if _, ok = expected[name]; !ok {
			return state, fmt.Errorf("Неизвестное значение: поле снимка HTTP SQLite %q", name)
		}
		if _, ok = seen[name]; ok {
			return state, fmt.Errorf("Обнаружен дубликат: поле снимка HTTP SQLite %q", name)
		}
		seen[name] = struct{}{}
		var value json.RawMessage
		if err = decoder.Decode(&value); err != nil {
			return state, err
		}
		if name == "private0373" {
			if err = validateSQLitePrivateFields0471(value); err != nil {
				return state, err
			}
		}
	}
	if _, err = decoder.Token(); err != nil {
		return state, err
	}
	if len(seen) != len(expected) {
		return state, fmt.Errorf("В снимке SQLite HTTP отсутствуют поля (%d/%d)", len(seen), len(expected))
	}
	var trailing any
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return state, errors.New("После снимка SQLite HTTP обнаружены лишние значения")
		}
		return state, err
	}
	if err = json.Unmarshal(raw, &state); err != nil {
		return state, err
	}
	if !validPrivateSQLite0373(state) {
		return state, errors.New("Секретное состояние SQLite HTTP не согласовано")
	}
	return state, nil
}

// Закрытые массивы содержат проверяющие пароли, refresh-токены и ключи устройств.
// Отсутствующие или дублирующиеся поля нельзя молча толковать как пустые секреты.
func validateSQLitePrivateFields0471(raw []byte) error {
	expected := make(map[string]struct{})
	typ := reflect.TypeOf(sqliteHTTPPrivate0373{})
	for i := 0; i < typ.NumField(); i++ {
		name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		expected[name] = struct{}{}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return errors.New("Приватное состояние SQLite HTTP: требуется объект")
	}
	seen := map[string]struct{}{}
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("Приватное свойство SQLite HTTP не является строкой")
		}
		if _, ok = expected[key]; !ok {
			return fmt.Errorf("Неизвестное значение: приватное свойство HTTP SQLite %q", key)
		}
		if _, ok = seen[key]; ok {
			return fmt.Errorf("Обнаружен дубликат: приватное свойство HTTP SQLite %q", key)
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return err
		}
	}
	if _, err = d.Token(); err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("В приватном снимке SQLite HTTP отсутствуют свойства (%d/%d)", len(seen), len(expected))
	}
	var trailing any
	if err = d.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("После приватного состояния SQLite HTTP обнаружены лишние данные")
		}
		return err
	}
	return nil
}

func (r *SQLiteHTTPRepository0372) Health(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed != nil {
		return r.failed
	}
	err := r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		var result string
		if e := q.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&result); e != nil {
			return e
		}
		if result != "ok" {
			return fmt.Errorf("Быстрая проверка SQLite HTTP: %s", result)
		}
		var seq int64
		var sha string
		var raw []byte
		if e := q.QueryRowContext(ctx, `SELECT sequence,sha256,document FROM http_repository_state_0372 WHERE singleton=1`).Scan(&seq, &sha, &raw); e != nil {
			return e
		}
		if seq != r.seq || sha != r.digest {
			return ErrConflict
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != sha {
			return errors.New("Контрольная сумма состояния SQLite HTTP не совпадает")
		}
		if _, e := decodeSQLiteHTTPDocument0471(raw); e != nil {
			return fmt.Errorf("Некорректное состояние SQLite HTTP: %w", e)
		}
		return nil
	})
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		r.failed = err
	}
	return err
}

func (r *SQLiteHTTPRepository0372) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.store == nil {
		return nil
	}
	err := r.store.Close()
	r.failed = sqlitedurable.ErrClosed
	return err
}

// Последнего активного владельца нельзя удалить обычными операциями с учётными
// записями.
func sqliteHTTPOtherActiveOwner0372(users []model.User, exceptID string) bool {
	for _, u := range users {
		if u.ID != exceptID && u.RoleID == "owner" && u.Status == "active" {
			return true
		}
	}
	return false
}

// Обработчики аудита запускаются только после успешной устойчивой фиксации и
// освобождения блокировки состояния, чтобы callbacks шины событий могли безопасно
// обращаться к репозиторию.
func (r *SQLiteHTTPRepository0372) unlockAndPublishAudit0372(start int) {
	var emitted []model.AuditEvent
	sink := r.auditSink
	if r.failed == nil && sink != nil && start < len(r.mem.audit) {
		emitted = append([]model.AuditEvent(nil), r.mem.audit[start:]...)
	}
	r.mu.Unlock()
	if sink != nil {
		for _, event := range emitted {
			sink(event)
		}
	}
}
