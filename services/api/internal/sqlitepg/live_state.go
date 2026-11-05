package sqlitepg

// Это офлайн-преобразование проверенных промежуточных строк Core в таблицы
// репозитория PostgreSQL. Оно выполняется в транзакции SERIALIZABLE
// функции PopulateLive0473. Недоверенные данные не копируются и
// сеансы/обработчики остановленной SQLite-установки не возрождаются.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const stateVersion0474 = "sqlite-core-state-to-sqlrepository-0474-v1"

type stateRule0474 struct {
	source, target string
	apply          func(context.Context, pgx.Tx, map[string]any) error
}

func mustText0474(src map[string]any, name string) (string, error) {
	v, ok := src[name].(string)
	if !ok {
		return "", fmt.Errorf("В %s ожидался текст", name)
	}
	return v, nil
}
func mustInt0474(src map[string]any, name string) (int64, error) {
	v, ok := src[name].(int64)
	if !ok {
		return 0, fmt.Errorf("В %s ожидалось целое число", name)
	}
	return v, nil
}
func when0474(src map[string]any, name string, optional bool) (any, error) {
	n, e := mustInt0474(src, name)
	if e != nil {
		return nil, e
	}
	return instant0473(n, optional)
}
func jsonText0474(src map[string]any, name string) (string, error) {
	s, e := mustText0474(src, name)
	if e != nil {
		return "", e
	}
	if !json.Valid([]byte(s)) {
		return "", fmt.Errorf("Некорректный JSON в %s", name)
	}
	return s, nil
}
func validatedHash0474(src map[string]any, name string) (string, error) {
	s, e := mustText0474(src, name)
	if e != nil {
		return "", e
	}
	if len(s) != 64 {
		return "", fmt.Errorf("Некорректное значение: %s длина", name)
	}
	if _, e = hex.DecodeString(s); e != nil {
		return "", fmt.Errorf("Некорректное значение: %s hex", name)
	}
	if strings.ToLower(s) != s {
		return "", fmt.Errorf("Недопустимый регистр символов в %s", name)
	}
	return s, nil
}
func digestJSON0474(src map[string]any, field, digest string) (string, error) {
	s, e := jsonText0474(src, field)
	if e != nil {
		return "", e
	}
	h, e := validatedHash0474(src, digest)
	if e != nil {
		return "", e
	}
	sum := sha256.Sum256([]byte(s))
	if hex.EncodeToString(sum[:]) != h {
		return "", fmt.Errorf("Контрольная сумма %s не совпадает", field)
	}
	return s, nil
}

// Схема Runtime не содержит Core auth_epoch и потому не может надёжно
// проверять уже выпущенные токены. Сохраняйте исходную эпоху и состояние сеансов,
// но отзывайте старые bearer-сеансы на границе доверия с обязательным повторным входом.
func session0474(ctx context.Context, tx pgx.Tx, s map[string]any) error {
	uid, e := mustText0474(s, "user_id")
	if e != nil {
		return e
	}
	sessionID, e := mustText0474(s, "id")
	if e != nil || sessionID == "" {
		return errors.New("Некорректное значение: идентификатор исходного сеанса")
	}
	var email, role string
	if e = tx.QueryRow(ctx, `SELECT email,role_id FROM users WHERE id=$1`, uid).Scan(&email, &role); e != nil {
		return e
	}
	var family string
	e = tx.QueryRow(ctx, `SELECT id FROM `+qualified("refresh_families")+` WHERE session_id=$1 ORDER BY CASE WHEN status='active' THEN 0 ELSE 1 END,id LIMIT 1`, s["id"]).Scan(&family)
	if errors.Is(e, pgx.ErrNoRows) {
		family = "imported-orphan-" + sessionID
	} else if e != nil {
		return e
	}
	epoch, e := mustInt0474(s, "auth_epoch")
	if e != nil {
		return e
	}
	if epoch < 1 {
		return errors.New("Некорректное значение: период актуальности авторизации сеанса")
	}
	methods, e := jsonText0474(s, "auth_methods")
	if e != nil {
		return e
	}
	created, e := when0474(s, "created_at", false)
	if e != nil {
		return e
	}
	seen, e := when0474(s, "last_seen_at", false)
	if e != nil {
		return e
	}
	expires, e := when0474(s, "expires_at", false)
	if e != nil {
		return e
	}
	revoked, e := when0474(s, "revoked_at", true)
	if e != nil {
		return e
	}
	status, e := mustText0474(s, "status")
	if e != nil {
		return e
	}
	if status != "active" && status != "revoked" {
		return fmt.Errorf("Некорректное значение: статус сеанса %s", status)
	}
	// Исходные учётные данные выпущены другим центром токенов.
	if status == "active" {
		status = "revoked"
		revoked = time.Now().UTC()
	}
	_, e = tx.Exec(ctx, `INSERT INTO auth_sessions(id,user_id,email,role_id,device_id,status,refresh_family_id,created_at,last_seen_at,expires_at,revoked_at,revoked_reason,auth_methods,core_auth_epoch_0474,core_original_status_0474,core_original_reason_0474)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15,$16)`, s["id"], uid, email, role, s["device_id"], status, family, created, seen, expires, revoked, "SQLite to PostgreSQL trust-boundary rotation", methods, epoch, s["status"], s["revoked_reason"])
	return e
}
func family0474(ctx context.Context, tx pgx.Tx, s map[string]any) error {
	var userID string
	if e := tx.QueryRow(ctx, `SELECT user_id FROM auth_sessions WHERE id=$1`, s["session_id"]).Scan(&userID); e != nil {
		return e
	}
	created, e := when0474(s, "created_at", false)
	if e != nil {
		return e
	}
	revoked, e := when0474(s, "revoked_at", true)
	if e != nil {
		return e
	}
	status, e := mustText0474(s, "status")
	if e != nil {
		return e
	}
	if status != "active" && status != "revoked" && status != "compromised" {
		return fmt.Errorf("Некорректное значение: статус семейства %s", status)
	}
	// Все старые refresh-токены отзываются, но их история сохраняется.
	_, e = tx.Exec(ctx, `INSERT INTO refresh_token_families(id,session_id,user_id,status,created_at,compromised_at,revoked_at,revoked_reason,core_original_status_0474)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, s["id"], s["session_id"], userID, "revoked", created, func() any {
		if status == "compromised" {
			return revoked
		}
		return nil
	}(), time.Now().UTC(), "Миграция SQLite: требуется повторная аутентификация", status)
	return e
}
func refresh0474(ctx context.Context, tx pgx.Tx, s map[string]any) error {
	hash, e := validatedHash0474(s, "token_hash")
	if e != nil {
		return e
	}
	var sessionID string
	if e = tx.QueryRow(ctx, `SELECT session_id FROM refresh_token_families WHERE id=$1`, s["family_id"]).Scan(&sessionID); e != nil {
		return e
	}
	created, e := when0474(s, "created_at", false)
	if e != nil {
		return e
	}
	expires, e := when0474(s, "expires_at", false)
	if e != nil {
		return e
	}
	consumed, e := when0474(s, "consumed_at", true)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO refresh_tokens(id,family_id,session_id,token_hash,status,created_at,expires_at,consumed_at,revoked_at,core_original_status_0474)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, "sqlite-"+hash, s["family_id"], sessionID, hash, "revoked", created, expires, consumed, time.Now().UTC(), s["status"])
	return e
}

// MFASecrets0474 содержит исходный ключ SQLite Core и целевой ключ PostgreSQL.
// Вызывающий должен передать оба для *каждой* прежней записи TOTP, включая
// незавершённые подключения. Ключ Core — сырые байты AES-256; PostgreSQLSecret — точно
// секрет API из securityPostgres111 без резервного ключа разработки.
type MFASecrets0474 struct {
	SQLiteMFAKey     []byte
	PostgreSQLSecret string
}

func rewrapTOTP0474(coreCipher []byte, keys MFASecrets0474) (string, error) {
	if len(keys.SQLiteMFAKey) != 32 || keys.PostgreSQLSecret == "" {
		return "", errors.New("для миграции MFA необходимы --sqlite-mfa-key-file и --postgres-secret-env; TOTP: запрещено «be disabled or copied as plaintext»")
	}
	block, err := aes.NewCipher(keys.SQLiteMFAKey)
	if err != nil {
		return "", err
	}
	old, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(coreCipher) < old.NonceSize()+old.Overhead() {
		return "", errors.New("Неполный секрет TOTP из SQLite")
	}
	seed, err := old.Open(nil, coreCipher[:old.NonceSize()], coreCipher[old.NonceSize():], []byte("Launcher/TOTP/0.32.3"))
	if err != nil {
		return "", errors.New("Ключ MFA SQLite не совпадает или зашифрованный секрет повреждён")
	}
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()
	if len(seed) != 20 {
		return "", errors.New("Секрет TOTP SQLite имеет неподдерживаемую длину")
	}
	text := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)
	derived := sha256.Sum256([]byte(keys.PostgreSQLSecret))
	block, err = aes.NewCipher(derived[:])
	if err != nil {
		return "", err
	}
	dst, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, dst.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	// Вывод ключа, кодирование и аутентифицированный конверт такие же, как в encryptString950.
	encrypted := dst.Seal(nonce, nonce, []byte(text), []byte("0.10.0"))
	return base64.RawURLEncoding.EncodeToString(encrypted), nil
}

func totpWithSecrets0474(ctx context.Context, tx pgx.Tx, s map[string]any, keys MFASecrets0474) error {
	raw, ok := s["secret_ciphertext"].([]byte)
	if !ok || len(raw) < 28 {
		return errors.New("Некорректное значение: зашифрованные данные TOTP ядра")
	}
	created, e := when0474(s, "created_at", false)
	if e != nil {
		return e
	}
	updated, e := when0474(s, "updated_at", false)
	if e != nil {
		return e
	}
	status, e := mustText0474(s, "status")
	if e != nil {
		return e
	}
	if status != "active" && status != "pending" {
		return errors.New("Неизвестное значение: TOTP статус")
	}
	step, e := mustInt0474(s, "last_step")
	if e != nil {
		return e
	}
	if step < -1 {
		return errors.New("Некорректное значение: счётчик предотвращения повторного использования TOTP")
	}
	encrypted, e := rewrapTOTP0474(raw, keys)
	if e != nil {
		return e
	}
	pending, active, pgStatus := "", "", "pending"
	if status == "active" {
		pgStatus = "enabled"
		active = encrypted
	} else {
		pending = encrypted
	}
	userID, e := mustText0474(s, "user_id")
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO mfa_methods(id,user_id,method_type,status,pending_secret_ciphertext,active_secret_ciphertext,created_at,updated_at,core_original_status_0474,core_last_step_0474)
     VALUES($1,$2,'totp',$3,$4,$5,$6,$7,$8,$9)`, "mfa-totp-"+userID, userID, pgStatus, pending, active, created, updated, status, step)
	return e
}

func recovery0474(ctx context.Context, tx pgx.Tx, s map[string]any) error {
	hash, e := validatedHash0474(s, "code_hash")
	if e != nil {
		return e
	}
	created, e := when0474(s, "created_at", false)
	if e != nil {
		return e
	}
	used, e := when0474(s, "used_at", true)
	if e != nil {
		return e
	}
	status := "active"
	if used != nil {
		status = "used"
	}
	_, e = tx.Exec(ctx, `INSERT INTO recovery_codes(id,user_id,method_id,code_hash,status,created_at,used_at)
     VALUES($1,$2,$3,$4,$5,$6,$7)`, "sqlite-recovery-"+hash, s["user_id"], "mfa-totp-"+s["user_id"].(string), hash, status, created, used)
	return e
}
func minecraftProfile0474(ctx context.Context, tx pgx.Tx, s map[string]any) error {
	created, e := when0474(s, "created_at", false)
	if e != nil {
		return e
	}
	updated, e := when0474(s, "updated_at", false)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO minecraft_profiles(user_id,uuid,name,created_at,updated_at,core_issuer_0474,core_realm_0474,core_subject_0474,core_identity_version_0474)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, s["user_id"], s["uuid"], s["name"], created, updated, s["issuer"], s["realm"], s["subject"], s["identity_version"])
	return e
}
func minecraftSession0474(ctx context.Context, tx pgx.Tx, s map[string]any) error {
	hash, e := validatedHash0474(s, "access_hash")
	if e != nil {
		return e
	}
	created, e := when0474(s, "created_at", false)
	if e != nil {
		return e
	}
	expires, e := when0474(s, "expires_at", false)
	if e != nil {
		return e
	}
	status, e := mustText0474(s, "status")
	if e != nil {
		return e
	}
	if status != "active" && status != "revoked" {
		return errors.New("Неизвестное значение: сеанс Minecraft состояние")
	}
	// После миграции токены доступа другого центра недействительны.
	_, e = tx.Exec(ctx, `INSERT INTO minecraft_sessions(id,user_id,session_id,profile_uuid,access_token_hash,status,created_at,last_seen_at,expires_at,revoked_at,revoked_reason,core_original_status_0474,core_original_reason_0474)
    VALUES($1,$2,$3,$4,$5,'revoked',$6,$6,$7,$8,$9,$10,$11)`, s["id"], s["user_id"], s["session_id"], s["profile_uuid"], hash, created, expires, time.Now().UTC(), "Миграция SQLite: требуется новый вход", status, s["revoked_reason"])
	return e
}
func revocation0474(ctx context.Context, tx pgx.Tx, s map[string]any) error {
	created, e := when0474(s, "created_at", false)
	if e != nil {
		return e
	}
	details, e := json.Marshal(map[string]any{"sqliteEventID": s["id"], "source": "sqlite-core", "reason": s["reason"]})
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO auth_events(user_id,session_id,event_type,details,created_at) VALUES($1,$2,'sqlite-session-revocation',$3::jsonb,$4)`, s["user_id"], s["session_id"], string(details), created)
	return e
}
func job0474(ctx context.Context, tx pgx.Tx, s map[string]any) error {
	payload, e := digestJSON0474(s, "payload", "payload_digest")
	if e != nil {
		return e
	}
	result, e := jsonText0474(s, "result")
	if e != nil {
		return e
	}
	status, e := mustText0474(s, "status")
	if e != nil {
		return e
	}
	fence, e := mustInt0474(s, "lease_fence")
	if e != nil {
		return e
	}
	if fence < 0 || fence == int64(^uint64(0)>>1) {
		return errors.New("Некорректное значение: блокировка задания")
	}
	available, e := when0474(s, "available_at", false)
	if e != nil {
		return e
	}
	created, e := when0474(s, "created_at", false)
	if e != nil {
		return e
	}
	updated, e := when0474(s, "updated_at", false)
	if e != nil {
		return e
	}
	completed, e := when0474(s, "completed_at", true)
	if e != nil {
		return e
	}
	owner, token := "", ""
	var lease any
	lastError := s["last_error"]
	if status == "running" {
		status = "pending"
		fence++
		available = time.Now().UTC()
		updated = available
		lastError = "Обработчик SQLite заблокирован на время миграции"
		completed = nil
	}
	_, e = tx.Exec(ctx, `INSERT INTO durable_jobs(id,kind,actor_type,actor_id,action,project_id,resource_type,resource_id,idempotency_key,payload,payload_digest,status,lease_owner,lease_token,lease_fence,lease_expires_at,attempt_count,max_attempts,available_at,last_error,result,created_at,updated_at,completed_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21::jsonb,$22,$23,$24)`, s["id"], s["kind"], s["actor_type"], s["actor_id"], s["action"], s["project_id"], s["resource_type"], s["resource_id"], s["idempotency_key"], payload, s["payload_digest"], status, owner, token, fence, lease, s["attempt_count"], s["max_attempts"], available, lastError, result, created, updated, completed)
	return e
}
func jobAttempt0474(ctx context.Context, tx pgx.Tx, s map[string]any) error {
	started, e := when0474(s, "started_at", false)
	if e != nil {
		return e
	}
	finished, e := when0474(s, "finished_at", true)
	if e != nil {
		return e
	}
	status, e := mustText0474(s, "status")
	if e != nil {
		return e
	}
	if status == "running" {
		status = "failed"
		finished = time.Now().UTC()
	}
	if status == "retry" || status == "expired" {
		status = "failed"
	}
	_, e = tx.Exec(ctx, `INSERT INTO durable_job_attempts(id,job_id,attempt,worker_id,lease_fence,started_at,finished_at,status,error,core_original_status_0474)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, s["id"], s["job_id"], s["attempt"], s["worker_id"], s["lease_fence"], started, finished, status, s["error"], s["status"])
	return e
}
func lease0474(ctx context.Context, tx pgx.Tx, s map[string]any) error {
	fence, e := mustInt0474(s, "fencing_token")
	if e != nil {
		return e
	}
	if fence < 1 || fence == int64(^uint64(0)>>1) {
		return errors.New("Некорректное значение: токен изоляции области")
	}
	// Прежний владелец не может продлевать аренду; новый в PostgreSQL получает больший токен.
	_, e = tx.Exec(ctx, `INSERT INTO durable_scope_leases(scope_key,owner,lease_token,fencing_token,expires_at,updated_at)
      VALUES($1,'','',$2,now() - interval '1 second',now())`, s["scope_key"], fence+1)
	return e
}
func outbox0474(ctx context.Context, tx pgx.Tx, s map[string]any) error {
	payload, e := digestJSON0474(s, "payload", "payload_digest")
	if e != nil {
		return e
	}
	status, e := mustText0474(s, "status")
	if e != nil {
		return e
	}
	fence, e := mustInt0474(s, "lease_fence")
	if e != nil {
		return e
	}
	if fence < 0 || fence == int64(^uint64(0)>>1) {
		return errors.New("Некорректное значение: блокировка исходящей очереди")
	}
	available, e := when0474(s, "available_at", false)
	if e != nil {
		return e
	}
	created, e := when0474(s, "created_at", false)
	if e != nil {
		return e
	}
	updated, e := when0474(s, "updated_at", false)
	if e != nil {
		return e
	}
	delivered, e := when0474(s, "delivered_at", true)
	if e != nil {
		return e
	}
	lastError := s["last_error"]
	if status == "running" {
		status = "pending"
		fence++
		available = time.Now().UTC()
		updated = available
		lastError = "Доставка через SQLite заблокирована на время миграции"
		delivered = nil
	}
	_, e = tx.Exec(ctx, `INSERT INTO event_outbox(id,event_type,project_id,aggregate_type,aggregate_id,actor_id,idempotency_key,payload,status,lease_owner,lease_token,lease_fence,lease_expires_at,attempt_count,max_attempts,available_at,last_error,created_at,updated_at,delivered_at,core_payload_digest_0474)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,'','',$10,NULL,$11,$12,$13,$14,$15,$16,$17,$18)`, s["id"], s["event_type"], s["project_id"], s["aggregate_type"], s["aggregate_id"], s["actor_id"], s["idempotency_key"], payload, status, fence, s["attempt_count"], s["max_attempts"], available, lastError, created, updated, delivered, s["payload_digest"])
	return e
}
func bridgeNode0474(ctx context.Context, tx pgx.Tx, s map[string]any) error {
	key, ok := s["public_key"].([]byte)
	if !ok || len(key) != 32 {
		return errors.New("Некорректное значение: ключ узла Ed25519")
	}
	fingerprint, e := validatedHash0474(s, "fingerprint")
	if e != nil {
		return e
	}
	sum := sha256.Sum256(key)
	if hex.EncodeToString(sum[:]) != fingerprint {
		return errors.New("Несовпадение: отпечаток ключа Ed25519 моста")
	}
	epoch, e := mustInt0474(s, "identity_epoch")
	if e != nil {
		return e
	}
	if epoch < 1 {
		return errors.New("Некорректное значение: период актуальности идентификатора моста")
	}
	created, e := when0474(s, "created_at", false)
	if e != nil {
		return e
	}
	updated, e := when0474(s, "updated_at", false)
	if e != nil {
		return e
	}
	status, e := mustText0474(s, "status")
	if e != nil {
		return e
	}
	if status != "active" && status != "disabled" {
		return errors.New("Некорректное значение: статус узла моста")
	}
	_, e = tx.Exec(ctx, `INSERT INTO server_bridge_nodes_v2(id,name,kind,project_id,profile_id,fingerprint,token_hash,token_prefix,status,protocol_version,created_at,key_algorithm,public_key,key_fingerprint,identity_epoch,identity_rotated_at,core_channel_0474)
     VALUES($1,$1,'velocity',$2,$3,$4,'','',$5,2,$6,'ed25519',$7,$4,$8,$9,$10)`, s["id"], s["project_id"], s["profile_id"], fingerprint, status, created, base64.RawURLEncoding.EncodeToString(key), epoch, updated, s["channel"])
	return e
}
func bridgeNonce0474(ctx context.Context, tx pgx.Tx, s map[string]any) error {
	_, e := validatedHash0474(s, "nonce_hash")
	if e != nil {
		return e
	}
	committed, e := when0474(s, "committed_at", false)
	if e != nil {
		return e
	}
	expires, e := when0474(s, "expires_at", false)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO server_bridge_node_nonces_v2(node_id,nonce_hash,identity_epoch,consumed_at,expires_at,core_action_0474)
     VALUES($1,$2,$3,$4,$5,$6)`, s["node_id"], s["nonce_hash"], s["identity_epoch"], committed, expires, s["action"])
	return e
}

// Старый формат подписанного токена намеренно НЕ принимается SQLRepository.
// Постоянные метки удалённых токенов сохраняют историю идентичности и отзыва,
// не предоставляя новым механизмам авторизации доступ по прежним учётным данным.
func accessToken0474(ctx context.Context, tx pgx.Tx, s map[string]any) error {
	hash, e := validatedHash0474(s, "token_hash")
	if e != nil {
		return e
	}
	issued, e := when0474(s, "issued_at", false)
	if e != nil {
		return e
	}
	expires, e := when0474(s, "expires_at", false)
	if e != nil {
		return e
	}
	revoked, e := when0474(s, "revoked_at", true)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO sqlite_access_token_tombstones_0474(token_hash,session_id,issued_at,expires_at,source_revoked_at,invalidated_at)
      VALUES($1,$2,$3,$4,$5,now())`, hash, s["session_id"], issued, expires, revoked)
	return e
}

func bridgeTicket0474(ctx context.Context, tx pgx.Tx, s map[string]any) error {
	hash, e := validatedHash0474(s, "token_hash")
	if e != nil {
		return e
	}
	created, e := when0474(s, "created_at", false)
	if e != nil {
		return e
	}
	expires, e := when0474(s, "expires_at", false)
	if e != nil {
		return e
	}
	consumed, e := when0474(s, "consumed_at", true)
	if e != nil {
		return e
	}
	terminal, e := when0474(s, "terminal_at", true)
	if e != nil {
		return e
	}
	status, e := mustText0474(s, "status")
	if e != nil {
		return e
	}
	if status != "active" && status != "consumed" && status != "replaced" && status != "invalidated" {
		return errors.New("Не поддерживается: состояние билета подключения")
	}
	original := status
	var invalidated any
	if status == "active" {
		status = "invalidated"
		invalidated = time.Now().UTC()
	} else if status == "replaced" || status == "invalidated" {
		invalidated = terminal
	}
	_, e = tx.Exec(ctx, `INSERT INTO server_bridge_join_tickets_v2(id,username,username_normalized,player_uuid,user_id,session_id,server_id,project_id,profile_id,channel,access_token_hash,minecraft_session_id,binding_epoch,status,created_at,expires_at,consumed_at,invalidated_at,core_original_status_0474,core_redeemed_nonce_0474,core_redeemed_ip_0474)
      VALUES($1,$2,lower($2),$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`, hash, s["username"], s["player_uuid"], s["user_id"], s["session_id"], s["node_id"], s["project_id"], s["profile_id"], s["channel"], s["access_token_hash"], s["minecraft_session_id"], s["issued_identity_epoch"], status, created, expires, consumed, invalidated, original, s["redeemed_nonce_hash"], s["redeemed_remote_ip"])
	return e
}

func bridgeRuntime0474(ctx context.Context, tx pgx.Tx, s map[string]any) error {
	id, e := validatedHash0474(s, "runtime_id")
	if e != nil {
		return e
	}
	epoch, e := mustInt0474(s, "epoch")
	if e != nil {
		return e
	}
	if epoch <= 0 || epoch == int64(^uint64(0)>>1) {
		return errors.New("Некорректное значение: период актуальности среды выполнения")
	}
	heartbeat, e := when0474(s, "last_heartbeat", false)
	if e != nil {
		return e
	}
	var updated int64
	e = tx.QueryRow(ctx, `UPDATE server_bridge_nodes_v2 SET runtime_id='',runtime_previous_id=$2,runtime_epoch=$3,
       runtime_last_seen_at=$4,core_runtime_status_0474=$5,core_runtime_heartbeat_seq_0474=$6,core_runtime_delivery_seq_0474=$7
       WHERE id=$1 RETURNING runtime_epoch`, s["node_id"], id, epoch+1, heartbeat, s["status"], s["heartbeat_seq"], s["delivery_seq"]).Scan(&updated)
	if e != nil {
		return e
	}
	if updated != epoch+1 {
		return errors.New("Несовпадение: блокировка поколения среды выполнения моста")
	}
	return nil
}

func runtimeNonce0474(ctx context.Context, tx pgx.Tx, s map[string]any) error {
	hash, e := validatedHash0474(s, "nonce_hash")
	if e != nil {
		return e
	}
	committed, e := when0474(s, "committed_at", false)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO sqlite_bridge_runtime_nonces_0474(node_id,epoch,nonce_hash,committed_at)
     VALUES($1,$2,$3,$4)`, s["node_id"], s["epoch"], hash, committed)
	return e
}

func bridgeCommand0474(ctx context.Context, tx pgx.Tx, s map[string]any) error {
	payload, e := digestJSON0474(s, "payload", "payload_digest")
	if e != nil {
		return e
	}
	result, e := jsonText0474(s, "result")
	if e != nil {
		return e
	}
	request, e := validatedHash0474(s, "request_digest")
	if e != nil {
		return e
	}
	created, e := when0474(s, "created_at", false)
	if e != nil {
		return e
	}
	updated, e := when0474(s, "updated_at", false)
	if e != nil {
		return e
	}
	expires, e := when0474(s, "expires_at", false)
	if e != nil {
		return e
	}
	completed, e := when0474(s, "completed_at", true)
	if e != nil {
		return e
	}
	status, e := mustText0474(s, "status")
	if e != nil {
		return e
	}
	switch status {
	case "pending", "leased":
		// Никогда не отправлять команду старому процессу. Сохранить идентичность
		// и результат, но заставить оператора подать новый запрос.
		status = "indeterminate"
		completed = time.Now().UTC()
	case "succeeded", "failed", "unsupported", "indeterminate", "expired":
	default:
		return errors.New("Не поддерживается: состояние команды ServerBridge")
	}
	_, e = tx.Exec(ctx, `INSERT INTO server_bridge_control_commands_v3(id,server_id,runtime_epoch,runtime_id,command_type,payload,payload_sha256,request_digest,requested_by,idempotency_key,status,attempt,created_at,updated_at,expires_at,completed_at,result,error,core_original_status_0474,core_delivery_seq_0474)
      VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17::jsonb,$18,$19,$20)`, s["id"], s["node_id"], s["runtime_epoch"], s["runtime_id"], s["command_type"], payload, s["payload_digest"], request, s["actor"], s["idempotency_key"], status, s["attempt"], created, updated, expires, completed, result, s["failure"], s["status"], s["delivery_seq"])
	return e
}

func stateRules0474() []stateRule0474 {
	return []stateRule0474{
		{"auth_sessions", "auth_sessions", session0474},
		{"access_tokens", "sqlite_access_token_tombstones_0474", accessToken0474},
		{"refresh_families", "refresh_token_families", family0474},
		{"refresh_tokens", "refresh_tokens", refresh0474},
		{"mfa_totp", "mfa_methods", func(context.Context, pgx.Tx, map[string]any) error { return errors.New("Отсутствует: ключ повторного шифрования MFA") }},
		{"mfa_recovery", "recovery_codes", recovery0474},
		{"minecraft_profiles", "minecraft_profiles", minecraftProfile0474},
		{"minecraft_sessions", "minecraft_sessions", minecraftSession0474},
		{"auth_revocation_events", "auth_events", revocation0474},
		{"durable_jobs", "durable_jobs", job0474},
		{"durable_job_attempts", "durable_job_attempts", jobAttempt0474},
		{"durable_scope_leases", "durable_scope_leases", lease0474},
		{"durable_outbox", "event_outbox", outbox0474},
		{"bridge_nodes", "server_bridge_nodes_v2", bridgeNode0474},
		{"bridge_nonces", "server_bridge_node_nonces_v2", bridgeNonce0474},
		{"bridge_join_tickets", "server_bridge_join_tickets_v2", bridgeTicket0474},
		{"bridge_runtime", "server_bridge_nodes_v2", bridgeRuntime0474},
		{"bridge_runtime_nonces", "sqlite_bridge_runtime_nonces_0474", runtimeNonce0474},
		{"bridge_commands", "server_bridge_control_commands_v3", bridgeCommand0474},
	}
}

func prepareState0474(ctx context.Context, tx pgx.Tx) error {
	// Исторические миграции неизменяемы. Дополнительные столбцы сохраняют поля,
	// которые зрелая модель PostgreSQL иначе не представляет.
	changes := []string{
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS core_auth_epoch_0474 BIGINT NOT NULL DEFAULT 1`,
		`ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS core_auth_epoch_0474 BIGINT NOT NULL DEFAULT 1`,
		`ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS core_original_status_0474 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS core_original_reason_0474 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE refresh_token_families ADD COLUMN IF NOT EXISTS core_original_status_0474 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS core_original_status_0474 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE minecraft_sessions ADD COLUMN IF NOT EXISTS core_original_status_0474 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE minecraft_sessions ADD COLUMN IF NOT EXISTS core_original_reason_0474 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE minecraft_profiles ADD COLUMN IF NOT EXISTS core_issuer_0474 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE minecraft_profiles ADD COLUMN IF NOT EXISTS core_realm_0474 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE minecraft_profiles ADD COLUMN IF NOT EXISTS core_subject_0474 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE minecraft_profiles ADD COLUMN IF NOT EXISTS core_identity_version_0474 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE mfa_methods ADD COLUMN IF NOT EXISTS core_original_status_0474 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE mfa_methods ADD COLUMN IF NOT EXISTS core_last_step_0474 BIGINT NOT NULL DEFAULT -1`,
		`ALTER TABLE event_outbox ADD COLUMN IF NOT EXISTS core_payload_digest_0474 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE durable_job_attempts ADD COLUMN IF NOT EXISTS core_original_status_0474 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE server_bridge_node_nonces_v2 ADD COLUMN IF NOT EXISTS core_action_0474 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE server_bridge_nodes_v2 ADD COLUMN IF NOT EXISTS core_channel_0474 TEXT NOT NULL DEFAULT 'stable'`,
		`ALTER TABLE server_bridge_nodes_v2 ADD COLUMN IF NOT EXISTS core_runtime_status_0474 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE server_bridge_nodes_v2 ADD COLUMN IF NOT EXISTS core_runtime_heartbeat_seq_0474 BIGINT NOT NULL DEFAULT 0`,
		`ALTER TABLE server_bridge_nodes_v2 ADD COLUMN IF NOT EXISTS core_runtime_delivery_seq_0474 BIGINT NOT NULL DEFAULT 0`,
		`ALTER TABLE server_bridge_join_tickets_v2 ADD COLUMN IF NOT EXISTS core_original_status_0474 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE server_bridge_join_tickets_v2 ADD COLUMN IF NOT EXISTS core_redeemed_nonce_0474 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE server_bridge_join_tickets_v2 ADD COLUMN IF NOT EXISTS core_redeemed_ip_0474 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE server_bridge_control_commands_v3 ADD COLUMN IF NOT EXISTS core_original_status_0474 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE server_bridge_control_commands_v3 ADD COLUMN IF NOT EXISTS core_delivery_seq_0474 BIGINT NOT NULL DEFAULT 0`,
		`CREATE TABLE IF NOT EXISTS sqlite_access_token_tombstones_0474(token_hash TEXT PRIMARY KEY,session_id TEXT NOT NULL REFERENCES auth_sessions(id),issued_at TIMESTAMPTZ NOT NULL,expires_at TIMESTAMPTZ NOT NULL,source_revoked_at TIMESTAMPTZ,invalidated_at TIMESTAMPTZ NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS sqlite_bridge_runtime_nonces_0474(node_id TEXT NOT NULL REFERENCES server_bridge_nodes_v2(id),epoch BIGINT NOT NULL,nonce_hash TEXT NOT NULL CHECK(length(nonce_hash)=64),committed_at TIMESTAMPTZ NOT NULL,PRIMARY KEY(node_id,epoch,nonce_hash))`,
	}
	for _, ddl := range changes {
		if _, e := tx.Exec(ctx, ddl); e != nil {
			return e
		}
	}
	return nil
}

func moveState0474(ctx context.Context, tx pgx.Tx, receipt Report, report *LiveReport0473, keys MFASecrets0474) error {
	if err := prepareState0474(ctx, tx); err != nil {
		return err
	}
	for _, r := range stateRules0474() {
		expected, ok := tableReport0473(receipt, r.source)
		if !ok {
			return fmt.Errorf("Отсутствует: таблица ядра %s", r.source)
		}
		if e := sourceRows0473(ctx, tx, r.source, expected, func(s map[string]any) error {
			if r.source == "mfa_totp" {
				return totpWithSecrets0474(ctx, tx, s, keys)
			}
			return r.apply(ctx, tx, s)
		}); e != nil {
			return fmt.Errorf("Ошибка перехода основного состояния %s -> %s: %w", r.source, r.target, e)
		}
		if r.source == "bridge_runtime" {
			var n int64
			if e := tx.QueryRow(ctx, `SELECT count(*) FROM server_bridge_nodes_v2 WHERE core_runtime_status_0474<>''`).Scan(&n); e != nil {
				return e
			}
			if n != expected.Rows {
				return fmt.Errorf("Несовпадение: количество строк среды выполнения моста: %d != %d", n, expected.Rows)
			}
		} else if r.source != "auth_revocation_events" {
			if e := verifyLive0473(ctx, tx, r.target, expected.Rows); e != nil {
				return e
			}
		} else {
			var n int64
			if e := tx.QueryRow(ctx, `SELECT count(*) FROM auth_events WHERE event_type='sqlite-session-revocation'`).Scan(&n); e != nil {
				return e
			}
			if n != expected.Rows {
				return errors.New("Несовпадение: число событий аудита отзыва")
			}
		}
		report.LiveTables = append(report.LiveTables, LiveTable0473{Source: r.source, Destination: r.target, Rows: expected.Rows})
	}
	// Исходные явные ID были скопированы в BIGSERIAL, поэтому следующая попытка PG
	// никогда не должна повторно использовать существующее значение.
	if _, e := tx.Exec(ctx, `SELECT setval(pg_get_serial_sequence('durable_job_attempts','id'), GREATEST(COALESCE((SELECT max(id) FROM durable_job_attempts),0),1),true)`); e != nil {
		return e
	}
	return nil
}
