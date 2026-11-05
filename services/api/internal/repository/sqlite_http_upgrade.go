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

	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

// Синтезировать можно только явно известные поля, добавленные позднее. Записи
// идентичностей, профилей, релизов и авторизации НИКОГДА не заменяются
// значениями по умолчанию.
var httpOptionalLegacyFields0472 = map[string]bool{
	"stagedRuntimeRuns0342": true, "validationAttestations0345": true,
	"validationAttempts03412": true, "validationChallenges0346": true, "validationRevocations0346": true,
	"extensionRegistryPublishers": true, "extensionRegistryKeys": true, "extensionRegistryVersions": true,
	"extensionInstallRevisions": true, "extensionEvents": true, "extensionEventSubscriptions": true,
	"extensionEventDeliveries": true, "extensionEventDeadLetters": true,
	"extensionPermissionGrants": true, "extensionSecrets": true, "extensionUpdatePins": true,
	"extensionUpdateTransactions": true, "extensionUpdateLeases": true, "extensionTrustPolicy": true,
	"extensionQuarantine": true, "extensionEmergencyDisables": true,
	"nextExtensionInstallRevisionID": true, "nextExtensionEventSequence": true,
	"nextExtensionSubscriptionID": true, "nextExtensionDeliveryID": true,
	"nextExtensionDeadLetterID": true,
}

func strictObject0472(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if tok != json.Delim('{') {
		return nil, errors.New("Ожидается объект JSON")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		tok, err = dec.Token()
		if err != nil {
			return nil, err
		}
		name, ok := tok.(string)
		if !ok {
			return nil, errors.New("Ключ JSON не является строкой")
		}
		if _, ok = out[name]; ok {
			return nil, fmt.Errorf("Обнаружен дубликат: «JSON property» %q", name)
		}
		var data json.RawMessage
		if err = dec.Decode(&data); err != nil {
			return nil, err
		}
		out[name] = data
	}
	if _, err = dec.Token(); err != nil {
		return nil, err
	}
	var tail any
	if err = dec.Decode(&tail); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("Обнаружены лишние данные после: JSON значения")
		}
		return nil, err
	}
	return out, nil
}
func fieldMap0472(t reflect.Type) map[string]reflect.Type {
	fields := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		fields[strings.Split(f.Tag.Get("json"), ",")[0]] = f.Type
	}
	return fields
}
func zeroJSON0472(t reflect.Type) (json.RawMessage, error) {
	return json.Marshal(reflect.Zero(t).Interface())
}

// Старая оболочка JSON v1 принимается только тогда, когда SQL-схема доказывает
// более ранний выпуск без добавленных позднее таблиц Runtime или stable-permit.
// Полностью инициализированные современные БД сохраняют строгий декодер 0.47.1.
func upgradeHTTPDocument0472(raw []byte) ([]byte, error) {
	root, err := strictObject0472(raw)
	if err != nil {
		return nil, err
	}
	fields := fieldMap0472(reflect.TypeOf(sqliteHTTPState0372{}))
	for key := range root {
		if _, ok := fields[key]; !ok {
			return nil, fmt.Errorf("Неизвестное значение: «HTTP legacy field» %q", key)
		}
	}
	// Отсутствующий верхний счётчик можно синтезировать лишь при пустой старой
	// коллекции. Никогда не сбрасывайте действующую последовательность в ноль.
	counterSources := map[string]string{
		"nextExtensionInstallRevisionID": "extensionInstallRevisions",
		"nextExtensionEventSequence":     "extensionEvents",
		"nextExtensionSubscriptionID":    "extensionEventSubscriptions",
		"nextExtensionDeliveryID":        "extensionEventDeliveries",
		"nextExtensionDeadLetterID":      "extensionEventDeadLetters",
	}
	// Нельзя безопасно выдумывать значения по умолчанию для доверия, отзыва и
	// карантина, если уже сохранены зависящие от них объекты.
	securitySources := map[string][]string{
		"extensionTrustPolicy":       {"extensionInstalls", "extensionRegistryKeys"},
		"extensionRegistryKeys":      {"extensionRegistryPublishers"},
		"extensionEmergencyDisables": {"extensionInstalls"},
		"extensionQuarantine":        {"extensionInstalls"},
		"validationRevocations0346":  {"validationAttestations0345"},
	}
	for key, t := range fields {
		if _, ok := root[key]; ok {
			continue
		}
		if key != "private0373" && !httpOptionalLegacyFields0472[key] {
			return nil, fmt.Errorf("Отсутствует: «required HTTP legacy field» %q", key)
		}
		deps := securitySources[key]
		if counterSources[key] != "" {
			deps = append(deps, counterSources[key])
		}
		for _, source := range deps {
			if data, ok := root[source]; ok {
				var items []json.RawMessage
				if err := json.Unmarshal(data, &items); err != nil {
					return nil, fmt.Errorf("Некорректное значение: «legacy %s data»: %w", source, err)
				}
				if len(items) != 0 {
					return nil, fmt.Errorf("Невозможно восстановить отсутствующее поле %s: заполнено %s", key, source)
				}
			}
		}
		v, e := zeroJSON0472(t)
		if e != nil {
			return nil, e
		}
		root[key] = v
	}
	// Устаревшие закрытые массивы не могут отсутствовать при заполненном публичном
	// срезе записей: создание пустых хешей паролей или токенов лишит доступа.
	priv, err := strictObject0472(root["private0373"])
	if err != nil {
		return nil, fmt.Errorf("Ошибка прежнего состояния авторизации: %w", err)
	}
	privateFields := fieldMap0472(reflect.TypeOf(sqliteHTTPPrivate0373{}))
	dependencies := map[string]string{
		"passwordHashes": "users", "providerRefresh": "providerCredentials",
		"devicePublicKeys": "trustedDevices", "deviceChallenges": "deviceChallenges",
		"minecraftSessions": "minecraftSessions", "minecraftJoinUsernames": "minecraftJoins",
		"hardwareEvidence": "hardwareEvidence", "measuredBoot": "measuredBoot0315",
		"extensionSecrets": "extensionSecrets", "extensionDeliveryTokens": "extensionEventDeliveries",
	}
	for key := range priv {
		if _, ok := privateFields[key]; !ok {
			return nil, fmt.Errorf("Неизвестное значение: «legacy authorization field» %q", key)
		}
	}
	for key, t := range privateFields {
		if _, ok := priv[key]; ok {
			continue
		}
		dep := dependencies[key]
		var arr []json.RawMessage
		if err = json.Unmarshal(root[dep], &arr); err != nil {
			return nil, fmt.Errorf("legacy %s: %w", dep, err)
		}
		if len(arr) > 0 {
			return nil, fmt.Errorf("Отсутствует: «private auth field %s for %d persisted %s records»", key, len(arr), dep)
		}
		val, e := zeroJSON0472(t)
		if e != nil {
			return nil, e
		}
		priv[key] = val
	}
	root["private0373"], err = json.Marshal(priv)
	if err != nil {
		return nil, err
	}
	updated, err := json.Marshal(root)
	if err != nil {
		return nil, err
	}
	if _, err = decodeSQLiteHTTPDocument0471(updated); err != nil {
		return nil, fmt.Errorf("Некорректное значение: «converted HTTP snapshot»: %w", err)
	}
	return updated, nil
}

func normalizeHTTPDDL0472(text string) string {
	return strings.ToLower(strings.ReplaceAll(strings.Join(strings.Fields(strings.TrimSuffix(strings.TrimSpace(text), ";")), ""), "ifnotexists", ""))
}
func httpDDL0472() map[string]string {
	defs := []string{sqliteHTTPDDL0372, sqliteRuntimeDDL0373, sqliteInstallationDDL0375}
	defs = append(defs, strings.Split(sqliteStablePermitDDL0374, ";")...)
	expected := map[string]string{}
	for _, raw := range defs {
		stmt := strings.TrimSpace(raw)
		if stmt == "" {
			continue
		}
		fields := strings.Fields(stmt)
		if len(fields) >= 6 {
			expected[fields[5]] = normalizeHTTPDDL0472(stmt)
		}
	}
	return expected
}

// Возвращает признак распознанной старой схемы и мигрированные байты.
// Предварительная проверка только для чтения выполняется до CREATE, UPDATE или
// резервного копирования.
func preflightHTTPUpgrade0472(ctx context.Context, store *sqlitedurable.Store, existing bool) (bool, []byte, error) {
	if !existing {
		return false, nil, nil
	}
	legacy := false
	var converted []byte
	err := store.Read(ctx, func(q sqlitedurable.Executor) error {
		expected := httpDDL0472()
		rows, err := q.QueryContext(ctx, `SELECT name,type,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND type IN ('table','index','view','trigger')`)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for rows.Next() {
			var name, typ string
			var ddl sql.NullString
			if err = rows.Scan(&name, &typ, &ddl); err != nil {
				break
			}
			want, ok := expected[name]
			if !ok || !ddl.Valid || normalizeHTTPDDL0472(ddl.String) != want {
				err = fmt.Errorf("Несовместимая версия SQLite HTTP %s %s", typ, name)
				break
			}
			seen[name] = true
		}
		if er := rows.Err(); err == nil {
			err = er
		}
		if er := rows.Close(); err == nil {
			err = er
		}
		if err != nil {
			return err
		}
		if !seen["http_repository_state_0372"] {
			return errors.New("Отсутствует: «SQLite HTTP snapshot table»")
		}
		for _, key := range []string{"http_runtime_components_0373", "http_stable_permits_0374", "http_stable_permits_package_0374"} {
			if !seen[key] {
				legacy = true
			}
		}
		var raw []byte
		var sha string
		var version int
		var seq int64
		if err = q.QueryRowContext(ctx, `SELECT state_version,sequence,sha256,document FROM http_repository_state_0372 WHERE singleton=1`).Scan(&version, &seq, &sha, &raw); err != nil {
			return err
		}
		var count int
		if err = q.QueryRowContext(ctx, `SELECT count(*) FROM http_repository_state_0372`).Scan(&count); err != nil {
			return err
		}
		if count != 1 || version != 1 || seq < 1 {
			return fmt.Errorf("Несовместимое состояние SQLite HTTP: version=%d, sequence=%d, rows=%d", version, seq, count)
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != sha {
			return errors.New("Несовпадение: «HTTP legacy state digest»")
		}
		if !legacy {
			_, err = decodeSQLiteHTTPDocument0471(raw)
			return err
		}
		converted, err = upgradeHTTPDocument0472(raw)
		return err
	})
	return legacy, converted, err
}

func migrateHTTPSnapshot0472(ctx context.Context, store *sqlitedurable.Store, converted []byte) error {
	sum := sha256.Sum256(converted)
	return store.Write(ctx, func(q sqlitedurable.Executor) error {
		var raw []byte
		var oldSHA string
		var version int
		var seq int64
		if err := q.QueryRowContext(ctx, `SELECT state_version,sequence,sha256,document FROM http_repository_state_0372 WHERE singleton=1`).Scan(&version, &seq, &oldSHA, &raw); err != nil {
			return err
		}
		oldSum := sha256.Sum256(raw)
		if version != 1 || seq < 1 || hex.EncodeToString(oldSum[:]) != oldSHA {
			return errors.New("Во время миграции изменилось состояние HTTP")
		}
		reencoded, err := upgradeHTTPDocument0472(raw)
		if err != nil {
			return err
		}
		if !bytes.Equal(reencoded, converted) {
			return errors.New("Снимок HTTP изменился после резервного копирования")
		}
		for _, stmt := range append([]string{sqliteRuntimeDDL0373}, strings.Split(sqliteStablePermitDDL0374, ";")...) {
			if strings.TrimSpace(stmt) == "" {
				continue
			}
			if _, err = q.ExecContext(ctx, stmt); err != nil {
				return err
			}
		}
		// CAS-обновление в той же транзакции SQLite, что и создание отсутствующих
		// таблиц.
		res, err := q.ExecContext(ctx, `UPDATE http_repository_state_0372 SET document=?, sha256=?,sequence=sequence+1 WHERE singleton=1 AND sequence=? AND sha256=?`, converted, hex.EncodeToString(sum[:]), seq, oldSHA)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return errors.New("Ошибка атомарного сравнения и замены (CAS) при обновлении HTTP")
		}
		return nil
	})
}
