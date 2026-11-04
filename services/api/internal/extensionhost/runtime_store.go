package extensionhost

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Extension-owned, durable JSON documents. Data lives outside signed package payloads,
// survives host restarts and extension upgrades, and is partitioned by extension+scope.
// Authorization is always checked in the broker; possession of a host token alone is
// insufficient to read/write state. Never persist secrets through this interface.
const runtimeValueLimit0303 = 128 << 10
const runtimeTotalLimit0303 = 4 << 20
const runtimeKeyLimit0303 = 256

var runtimeKeyPattern0303 = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

func runtimeDir0303(root string, key Key) string {
	h := sha256.Sum256([]byte(key.normalized().String()))
	return filepath.Join(root, "runtime-data", hex.EncodeToString(h[:]))
}

func secureDirectory0303(dir string) error {
	// Reject symlinks at each existing component; a malicious extension must not
	// redirect broker writes through a pre-planted symlink.
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	sep := string(filepath.Separator)
	current := filepath.VolumeName(dir) + sep
	for _, part := range strings.Split(strings.TrimPrefix(dir, current), sep) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		st, e := os.Lstat(current)
		if errors.Is(e, os.ErrNotExist) {
			if e = os.Mkdir(current, 0700); e != nil && !errors.Is(e, os.ErrExist) {
				return e
			}
			st, e = os.Lstat(current)
		}
		if e != nil {
			return e
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("runtime state parent is not a real directory: %s", current)
		}
	}
	return nil
}

func runtimeFile0303(dir, kind, key string) (string, error) {
	if !runtimeKeyPattern0303.MatchString(key) {
		return "", errors.New("invalid runtime document key")
	}
	if kind != "config" && kind != "storage" {
		return "", errors.New("invalid runtime document kind")
	}
	hash := sha256.Sum256([]byte(kind + ":" + key))
	return filepath.Join(dir, kind+"-"+hex.EncodeToString(hash[:])+".json"), nil
}

func runtimeWrite0303(ctx context.Context, dir, path string, body json.RawMessage) error {
	if !json.Valid(body) || len(body) > runtimeValueLimit0303 {
		return errors.New("runtime value must be JSON <= 128 KiB")
	}
	if err := secureDirectory0303(dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	total, count := int64(len(body)), 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("runtime state contains non-regular file")
		}
		if filepath.Join(dir, entry.Name()) != path {
			total += info.Size()
			count++
		}
	}
	if total > runtimeTotalLimit0303 || count >= runtimeKeyLimit0303 {
		return errors.New("runtime state quota exceeded")
	}
	name := make([]byte, 16)
	if _, err := rand.Read(name); err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".tmp-"+hex.EncodeToString(name))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err = f.Write(body); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// Best-effort directory sync for crash consistency on filesystems that support it.
	syncRuntimeDirectory0303(dir)
	return nil
}

// Directory syncing makes both rename and unlink durable on filesystems that
// support it. Platforms without directory fsync retain the prior best-effort
// behavior rather than making every document mutation fail.
func syncRuntimeDirectory0303(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

func runtimeRead0303(dir, path string) (json.RawMessage, bool, error) {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !st.Mode().IsRegular() || st.Size() > runtimeValueLimit0303 {
		return nil, false, errors.New("unsafe runtime state file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, runtimeValueLimit0303+1))
	if err != nil {
		return nil, false, err
	}
	if len(body) > runtimeValueLimit0303 || !json.Valid(body) {
		return nil, false, errors.New("runtime state is corrupt")
	}
	return body, true, nil
}

func (s *Supervisor) executeRuntime0303(ctx context.Context, st *processState, capName string, req capabilityRequest) capabilityResult0205 {
	parts := strings.Split(capName, ".")
	if len(parts) != 3 || parts[0] != "runtime" || (parts[1] != "config" && parts[1] != "storage") || (parts[2] != "get" && parts[2] != "put" && parts[2] != "delete") {
		return capabilityResult0205{status: 404, err: errors.New("unknown runtime operation")}
	}
	permission := "storage:read"
	if parts[2] != "get" {
		permission = "storage:write"
	}
	ok, err := s.permissionAllowed0207(ctx, st, permission, "")
	if err != nil {
		return capabilityResult0205{status: 503, err: errors.New("capability policy unavailable")}
	}
	if !ok {
		return capabilityResult0205{status: 403, err: fmt.Errorf("permission %s not granted", permission)}
	}
	dir := runtimeDir0303(s.cfg.ExtensionRoot, st.key)
	path, err := runtimeFile0303(dir, parts[1], req.Key)
	if err != nil {
		return capabilityResult0205{status: 400, err: err}
	}
	s.runtimeMu0303.Lock()
	defer s.runtimeMu0303.Unlock()
	if err := secureDirectory0303(dir); err != nil {
		return capabilityResult0205{status: 500, err: err}
	}
	if parts[2] == "put" {
		if len(req.Value) == 0 {
			return capabilityResult0205{status: 400, err: errors.New("value is required")}
		}
		if err := runtimeWrite0303(ctx, dir, path, req.Value); err != nil {
			return capabilityResult0205{status: 400, err: err}
		}
		return capabilityResult0205{status: 200, value: map[string]any{"saved": true}}
	}
	if parts[2] == "delete" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return capabilityResult0205{status: 500, err: err}
		}
		syncRuntimeDirectory0303(dir)
		return capabilityResult0205{status: 200, value: map[string]any{"deleted": true}}
	}
	body, found, err := runtimeRead0303(dir, path)
	if err != nil {
		return capabilityResult0205{status: 500, err: err}
	}
	if !found {
		return capabilityResult0205{status: 404, err: errors.New("runtime key not found")}
	}
	return capabilityResult0205{status: 200, value: map[string]any{"value": body}}
}
