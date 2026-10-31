// Package authupgrade performs a real PostgreSQL, read-only preservation scan
// before a Launcher authentication upgrade and checks it again afterwards.
// It never copies credentials, active sessions or raw account identifiers into
// the durable checkpoint. The normal sealed migration runner performs writes.
package authupgrade

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

const CheckpointVersion = 1
const maxRows = 2000000

type Digest struct {
	Count  int64  `json:"count"`
	SHA256 string `json:"sha256"`
}

type Checkpoint struct {
	SchemaVersion    int               `json:"schemaVersion"`
	CapturedAt       time.Time         `json:"capturedAt"`
	Scope            string            `json:"scope"`
	Identity         map[string]Digest `json:"identity"`
	AllowedProviders []string          `json:"allowedProviders"`
	PasswordFormats  map[string]int64  `json:"passwordFormats"`
	Providers        map[string]int64  `json:"providers"`
}

type scanRow struct {
	Kind string `json:"kind"`
	A    string `json:"a"`
	B    string `json:"b"`
	C    string `json:"c"`
	D    string `json:"d"`
}

// ReadOnlyScanSQL supports both the pre-0081 canonical schema and the new one:
// issuer is checked when present and fingerprinted using the exact legacy
// backfill namespace when missing. A legitimate 0081 migration preserves it.
const ReadOnlyScanSQL = `\set ON_ERROR_STOP on
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '120s';
SET LOCAL lock_timeout = '5s';
DO $nl$
DECLARE bad BIGINT;
BEGIN
 IF to_regclass('users') IS NULL OR to_regclass('auth_identities') IS NULL OR to_regclass('minecraft_profiles') IS NULL THEN
  RAISE EXCEPTION 'auth upgrade: required identity tables absent';
 END IF;
 SELECT count(*) INTO bad FROM auth_identities i LEFT JOIN users u ON i.user_id=u.id WHERE u.id IS NULL;
 IF bad<>0 THEN RAISE EXCEPTION 'auth upgrade: orphaned auth identities: %',bad; END IF;
 SELECT count(*) INTO bad FROM minecraft_profiles p LEFT JOIN users u ON p.user_id=u.id WHERE u.id IS NULL;
 IF bad<>0 THEN RAISE EXCEPTION 'auth upgrade: orphaned Minecraft profiles: %',bad; END IF;
 SELECT count(*) INTO bad FROM (SELECT lower(uuid) FROM minecraft_profiles GROUP BY lower(uuid) HAVING count(*)>1) t;
 IF bad<>0 THEN RAISE EXCEPTION 'auth upgrade: duplicate Minecraft UUID: %',bad; END IF;
 SELECT count(*) INTO bad FROM (SELECT lower(name) FROM minecraft_profiles GROUP BY lower(name) HAVING count(*)>1) t;
 IF bad<>0 THEN RAISE EXCEPTION 'auth upgrade: duplicate Minecraft profile name: %',bad; END IF;
 SELECT count(*) INTO bad FROM (SELECT lower(email) FROM users GROUP BY lower(email) HAVING count(*)>1) t;
 IF bad<>0 THEN RAISE EXCEPTION 'auth upgrade: duplicate account email: %',bad; END IF;
 IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='auth_identities' AND column_name='issuer') THEN
  EXECUTE 'SELECT count(*) FROM auth_identities WHERE issuer IS NULL OR issuer='''' OR issuer<>btrim(issuer) OR length(issuer)>2048 OR issuer ~ ''[[:space:][:cntrl:]]'' OR (provider=''local'' AND issuer<>''launcher'')' INTO bad;
  IF bad<>0 THEN RAISE EXCEPTION 'auth upgrade: invalid issuer: %',bad; END IF;
  EXECUTE 'SELECT count(*) FROM (SELECT provider,issuer,subject FROM auth_identities GROUP BY provider,issuer,subject HAVING count(*)>1) t' INTO bad;
  IF bad<>0 THEN RAISE EXCEPTION 'auth upgrade: issuer-scoped subject collision: %',bad; END IF;
 END IF;
END
$nl$;
-- Stable canonical fields only. A one-way digest of each stored password
-- hash detects accidental resets without exporting the hash. External claims,
-- sessions and access/refresh tokens are never SELECTed by this scan.
SELECT row_to_json(v)::text FROM (
 SELECT 'meta'::text kind, 'scan-v1'::text a, ''::text b, ''::text c, ''::text d
 UNION ALL SELECT 'user'::text kind, id::text a, email::text b, coalesce(display_name,'')::text c, jsonb_build_array(role_id, md5(coalesce(password_hash,'')))::text d FROM users
 UNION ALL SELECT 'identity', i.id::text, i.user_id::text, i.provider::text, jsonb_build_array(i.subject, coalesce(to_jsonb(i)->>'issuer', CASE WHEN i.provider='local' THEN 'launcher' ELSE 'provider:' || i.provider END))::text FROM auth_identities i
 UNION ALL SELECT 'profile', p.user_id::text, p.uuid::text, p.name::text, jsonb_build_array(to_jsonb(p)->>'issuer',to_jsonb(p)->>'realm',to_jsonb(p)->>'subject',to_jsonb(p)->>'identity_version')::text FROM minecraft_profiles p
 UNION ALL SELECT 'provider', provider::text, count(*)::text, '', '' FROM auth_identities GROUP BY provider
 UNION ALL SELECT 'password', format::text, count(*)::text, '', '' FROM (
  SELECT CASE
   WHEN password_hash IS NULL OR password_hash='' THEN 'none'
   WHEN password_hash ~ '^\$argon2id\$v=19\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$' THEN 'argon2id'
   WHEN password_hash ~ '^sha256:[0-9a-f]{64}$' THEN 'sha256-legacy'
   WHEN password_hash ~ '^\$never-gravit\$v1\$(sha256-hex|sha256-base64url|md5-hex|sha1-hex|sha512-hex|double-sha256-hex|double-sha256-binary-hex|phpass|bcrypt|argon2id)\$[A-Za-z0-9_-]+$' THEN 'fileauth-legacy'
   ELSE 'unsupported'
  END AS format FROM users
 ) formats GROUP BY format
) v ORDER BY v.kind,v.a,v.b,v.c,v.d;
COMMIT;
`

// ScanPSQL uses a child process because the CLI's migration runner also uses
// psql. stdout is parsed incrementally; no secrets are written to report files.
func ScanPSQL(ctx context.Context, executable, dsn string, allow []string) (Checkpoint, error) {
	if strings.TrimSpace(dsn) == "" {
		return Checkpoint{}, errors.New("LAUNCHER_DATABASE_DSN is required")
	}
	if executable == "" {
		executable = "psql"
	}
	cmd := exec.CommandContext(ctx, executable, "-X", "-q", "-A", "-t", "--no-psqlrc", "--set", "ON_ERROR_STOP=1", "--dbname", dsn)
	cmd.Stdin = strings.NewReader(ReadOnlyScanSQL)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Checkpoint{}, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &boundedWriter{w: &stderr, limit: 8192}
	if err = cmd.Start(); err != nil {
		return Checkpoint{}, fmt.Errorf("start psql: %w", err)
	}
	checkpoint, scanErr := ScanRows(stdout, allow)
	if scanErr != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if waitErr != nil && stderr.Len() > 0 && (scanErr == nil || strings.Contains(scanErr.Error(), "empty PostgreSQL auth scan") || strings.Contains(scanErr.Error(), "incomplete PostgreSQL auth scan")) {
		return Checkpoint{}, fmt.Errorf("PostgreSQL rejected auth migration preflight: %w (%s)", waitErr, strings.TrimSpace(stderr.String()))
	}
	if scanErr != nil {
		return Checkpoint{}, scanErr
	}
	if waitErr != nil {
		return Checkpoint{}, fmt.Errorf("read-only auth migration scan failed: %w (%s)", waitErr, strings.TrimSpace(stderr.String()))
	}
	return checkpoint, nil
}

type boundedWriter struct {
	w     io.Writer
	limit int
}

func (b *boundedWriter) Write(p []byte) (int, error) {
	n := len(p)
	if b.limit > 0 {
		c := p
		if len(c) > b.limit {
			c = c[:b.limit]
		}
		_, _ = b.w.Write(c)
		b.limit -= len(c)
	}
	return n, nil
}

func ScanRows(r io.Reader, allow []string) (Checkpoint, error) {
	permitted := map[string]bool{"local": true}
	for _, name := range allow {
		if name == "" || strings.TrimSpace(name) != name || len(name) > 128 || strings.ContainsAny(name, "\r\n\x00") {
			return Checkpoint{}, fmt.Errorf("invalid permitted provider ID")
		}
		permitted[name] = true
	}
	h := map[string]hash.Hash{"user": sha256.New(), "identity": sha256.New(), "profile": sha256.New()}
	counters := map[string]int64{"user": 0, "identity": 0, "profile": 0}
	cp := Checkpoint{SchemaVersion: CheckpointVersion, CapturedAt: time.Now().UTC(), Scope: "auth-identity-preservation-v1", Identity: make(map[string]Digest), Providers: make(map[string]int64), PasswordFormats: make(map[string]int64)}
	for k := range permitted {
		if k != "local" {
			cp.AllowedProviders = append(cp.AllowedProviders, k)
		}
	}
	sort.Strings(cp.AllowedProviders)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	rows := 0
	sawMeta := false
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		rows++
		if rows > maxRows {
			return Checkpoint{}, errors.New("auth upgrade scan exceeds 2 million rows")
		}
		var x scanRow
		if err := json.Unmarshal(line, &x); err != nil {
			return Checkpoint{}, fmt.Errorf("invalid database scan row %d: %w", rows, err)
		}
		switch x.Kind {
		case "meta":
			if x.A != "scan-v1" || sawMeta {
				return Checkpoint{}, errors.New("invalid scan marker")
			}
			sawMeta = true
		case "user", "identity", "profile":
			if x.A == "" || x.B == "" {
				return Checkpoint{}, errors.New("malformed identity record in database scan")
			}
			// Re-encode to canonical JSON, not psql-specific whitespace.
			encoded, _ := json.Marshal(x)
			_, _ = h[x.Kind].Write(encoded)
			_, _ = h[x.Kind].Write([]byte{'\n'})
			counters[x.Kind]++
		case "provider":
			var n int64
			var err error
			n, err = strconv.ParseInt(x.B, 10, 64)
			if err != nil || n < 0 || x.A == "" {
				return Checkpoint{}, errors.New("invalid provider count")
			}
			cp.Providers[x.A] += n
		case "password":
			var n int64
			var err error
			n, err = strconv.ParseInt(x.B, 10, 64)
			if err != nil || n < 0 {
				return Checkpoint{}, errors.New("invalid password classification count")
			}
			cp.PasswordFormats[x.A] += n
		default:
			return Checkpoint{}, fmt.Errorf("unknown auth scan row kind %q", x.Kind)
		}
	}
	if err := scanner.Err(); err != nil {
		return Checkpoint{}, err
	}
	if rows == 0 {
		return Checkpoint{}, errors.New("empty PostgreSQL auth scan; no checkpoint generated")
	}
	if !sawMeta {
		return Checkpoint{}, errors.New("incomplete PostgreSQL auth scan marker")
	}
	var totalPassword, totalProviders int64
	for _, n := range cp.PasswordFormats {
		totalPassword += n
	}
	for _, n := range cp.Providers {
		totalProviders += n
	}
	if totalPassword != counters["user"] || totalProviders != counters["identity"] {
		return Checkpoint{}, errors.New("auth scan count mismatch; refusing incomplete checkpoint")
	}
	if cp.PasswordFormats["unsupported"] > 0 {
		return Checkpoint{}, fmt.Errorf("%d unknown password hashes block automatic migration", cp.PasswordFormats["unsupported"])
	}
	for provider, n := range cp.Providers {
		if n > 0 && !permitted[provider] {
			return Checkpoint{}, fmt.Errorf("provider %q is not verified: explicitly acknowledge via --allow-provider after validating its issuer and custom implementation", provider)
		}
	}
	for k, hasher := range h {
		cp.Identity[k] = Digest{Count: counters[k], SHA256: hex.EncodeToString(hasher.Sum(nil))}
	}
	return cp, nil
}

func Compare(before, after Checkpoint) error {
	if before.SchemaVersion != CheckpointVersion || before.Scope != "auth-identity-preservation-v1" {
		return errors.New("unsupported or corrupted checkpoint version")
	}
	for _, kind := range []string{"user", "identity", "profile"} {
		if before.Identity[kind] != after.Identity[kind] {
			return fmt.Errorf("%s preservation fingerprint or row count changed; stop rollout and investigate, do NOT merge or rewrite identities", kind)
		}
	}
	if len(before.AllowedProviders) != len(after.AllowedProviders) {
		return errors.New("checkpoint provider allowlist mismatch")
	}
	for i, v := range before.AllowedProviders {
		if after.AllowedProviders[i] != v {
			return errors.New("checkpoint provider allowlist mismatch")
		}
	}
	return nil
}

func Save(path string, c Checkpoint) error {
	if path == "" {
		return errors.New("checkpoint output path is required")
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	fd, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer fd.Close()
	if _, err = fd.Write(data); err != nil {
		_ = os.Remove(path)
		return err
	}
	if err = fd.Sync(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func Load(path string) (Checkpoint, error) {
	var cp Checkpoint
	fd, err := os.Open(path)
	if err != nil {
		return cp, err
	}
	defer fd.Close()
	raw, err := io.ReadAll(io.LimitReader(fd, 128<<10))
	if err != nil {
		return cp, err
	}
	if len(raw) >= 128<<10 {
		return cp, errors.New("checkpoint too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&cp); err != nil {
		return cp, err
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return cp, errors.New("checkpoint contains trailing data")
	}
	if cp.SchemaVersion != CheckpointVersion || cp.Scope != "auth-identity-preservation-v1" {
		return cp, errors.New("unsupported checkpoint")
	}
	for _, name := range []string{"user", "identity", "profile"} {
		d, ok := cp.Identity[name]
		if !ok || len(d.SHA256) != 64 || d.Count < 0 {
			return cp, fmt.Errorf("malformed checkpoint %s", name)
		}
	}
	return cp, nil
}
