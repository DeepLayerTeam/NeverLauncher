// Package gravitidentity extracts identity records from real Gravit FileAuthSystem
// Database.json and explicit SQL CSV snapshots without executing modules or
// importing credentials. It never derives UUIDs from names.
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
	Ready           bool           `json:"ready"` // All UUIDs matched; does NOT authorize cutover.
}

func UUID(s string) (string, error) {
	s = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), "-", ""))
	if !uuidPattern.MatchString(s) || s == strings.Repeat("0", 32) {
		return "", errors.New("invalid Minecraft UUID")
	}
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}
func normalized(a Account) (Account, error) {
	if !usernamePattern.MatchString(a.Username) {
		return a, fmt.Errorf("invalid Minecraft username %q", a.Username)
	}
	if a.SourceID == "" || len(a.SourceID) > 256 || strings.TrimSpace(a.SourceID) != a.SourceID {
		return a, errors.New("missing/invalid stable source account ID")
	}
	var e error
	a.UUID, e = UUID(a.UUID)
	return a, e
}

// StrictRootMap rejects duplicate JSON keys at the root, a common source of
// silent account overwrites in Java/Gson-style databases.
func strictRootMap(b []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return nil, errors.New("expected FileAuth JSON UUID map")
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		token, e := d.Token()
		if e != nil {
			return nil, e
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("invalid key")
		}
		if _, exists := out[strings.ToLower(key)]; exists {
			return nil, fmt.Errorf("duplicate source identity key %q", key)
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
		return nil, errors.New("trailing data in FileAuth JSON")
	}
	return out, nil
}

// Reject duplicate fields inside each user object: encoding/json otherwise
// silently accepts the last username/UUID, masking contradictory identities.
func uniqueUserFields(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return errors.New("FileAuth user must be a JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("invalid FileAuth user key")
		}
		if seen[key] {
			return fmt.Errorf("duplicate FileAuth user field %q", key)
		}
		seen[key] = true
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
		return errors.New("trailing FileAuth user fields")
	}
	return nil
}

func parseFileAuth(b []byte, pathname string) ([]Account, error) {
	root, e := strictRootMap(b)
	if e != nil {
		return nil, e
	}
	if len(root) > MaxAccounts {
		return nil, errors.New("too many FileAuth accounts")
	}
	accounts := make([]Account, 0, len(root))
	for key, raw := range root {
		if err := uniqueUserFields(raw); err != nil {
			return nil, fmt.Errorf("FileAuth user %s: %w", key, err)
		}
		var obj struct {
			Username string `json:"username"`
			UUID     string `json:"uuid"`
		}
		if e = json.Unmarshal(raw, &obj); e != nil {
			return nil, fmt.Errorf("FileAuth user %s: %w", key, e)
		}
		canonicalKey, e := UUID(key)
		if e != nil {
			return nil, fmt.Errorf("FileAuth map key: %w", e)
		}
		if obj.UUID != "" {
			embedded, e := UUID(obj.UUID)
			if e != nil || canonicalKey != embedded {
				return nil, fmt.Errorf("FileAuth UUID mismatch for %q", key)
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
			return nil, errors.New("duplicate SQL CSV column")
		}
		cols[c] = i
	}
	// Gravit 5.7 documented SQL users columns are configurable; SQL export is
	// normalized by the operator to id,username,uuid rather than guessed from SQL.
	for _, c := range []string{"id", "username", "uuid"} {
		if _, ok := cols[c]; !ok {
			return nil, fmt.Errorf("SQL CSV missing %s column", c)
		}
	}
	out := []Account{}
	for row := 2; ; row++ {
		fields, e := reader.Read()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, fmt.Errorf("SQL CSV row %d: %w", row, e)
		}
		if len(fields) != len(header) {
			return nil, fmt.Errorf("SQL CSV row %d: unexpected column count", row)
		}
		a, e := normalized(Account{Provider: "sql", SourceID: fields[cols["id"]], Username: fields[cols["username"]], UUID: fields[cols["uuid"]], SourcePath: pathname})
		if e != nil {
			return nil, fmt.Errorf("SQL CSV row %d: %w", row, e)
		}
		out = append(out, a)
		if len(out) > MaxAccounts {
			return nil, errors.New("too many SQL accounts")
		}
	}
	return out, nil
}

// Extract consumes a complete source archive and only reads recognized account
// locations. Passwords, tokens, permissions and session fields are discarded.
// The exact zip bytes must already be bound to the durable 0.33.3 inventory.
func Extract(ctx context.Context, src io.ReaderAt, size int64, snapshot inv.Inventory) ([]Account, error) {
	checked, e := inv.Inspect(ctx, src, size, snapshot.SourceSHA256)
	if e != nil {
		return nil, e
	}
	if checked.ManifestSHA256 != snapshot.ManifestSHA256 || checked.SourceBytes != snapshot.SourceBytes {
		return nil, errors.New("source archive changed after inventory")
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
			return nil, fmt.Errorf("identity source %q too large", f.Name)
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
			return nil, errors.New("identity source overflow")
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
			return nil, errors.New("too many source accounts")
		}
	}
	if selected == 0 {
		return nil, errors.New("no supported FileAuthSystem/Database.json or sql-export/users.csv identity snapshot found")
	}
	if len(accounts) == 0 {
		return nil, errors.New("source identity snapshot has no accounts")
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

// Reconcile detects duplicate source identities and collisions across the
// complete Never identity namespace. A name alone is NEVER linking evidence.
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
		// A verified official link can mirror the same local Minecraft profile.
		// Only identical ownership+name is de-duplicated, never conflicting claims.
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
		m := Mapping{Account: a, Status: "pending_import", Reason: "no matching Never identity; reserved for subsequent authenticated account import"}
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
				m.Reason = "multiple Never identities claim UUID or username"
			} else if len(uuidOwners) == 1 {
				owner := uuidOwners[0]
				if !strings.EqualFold(owner.Username, a.Username) || (len(nameOwners) == 1 && nameOwners[0].UserID != owner.UserID) {
					m.Status = "blocked"
					m.Reason = "Never UUID ownership/name collision"
				} else {
					m.TargetUserID = owner.UserID
					m.Status = "matched"
					m.Reason = "exact Never UUID and username match; target ownership must be reverified before cutover"
				}
			} else if len(nameOwners) != 0 {
				m.Status = "blocked"
				m.Reason = "username already belongs to a different Never UUID"
			}
		}
		sum[m.Status]++
		rows = append(rows, m)
	}
	return rows, sum
}
