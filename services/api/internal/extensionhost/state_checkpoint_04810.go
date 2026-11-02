package extensionhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Durable copy-on-upgrade checkpoints of extension-owned JSON runtime documents.
// The supervisor serializes copies with broker mutations via runtimeMu0303;
// callers must stop the old Java Host before calling Snapshot. Snapshots are
// stored independently of signed payloads, and are never executable.
const checkpointMaxFiles04810 = runtimeKeyLimit0303
const checkpointMaxBytes04810 = runtimeTotalLimit0303

var checkpointTx04810 = regexp.MustCompile(`^extupd-[0-9a-f]{24}$`)
var checkpointFile04810 = regexp.MustCompile(`^(config|storage)-[0-9a-f]{64}\.json$`)

type checkpointFileEntry04810 struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}
type checkpointManifest04810 struct {
	Format int                        `json:"format"`
	Absent bool                       `json:"absent"`
	Files  []checkpointFileEntry04810 `json:"files"`
}

func checkpointPath04810(root string, key Key, txID string) (string, error) {
	if !checkpointTx04810.MatchString(txID) {
		return "", errors.New("invalid extension update transaction id")
	}
	normalized := key.normalized()
	digest := sha256.Sum256([]byte(normalized.String()))
	return filepath.Join(root, "runtime-upgrade-checkpoints", txID, hex.EncodeToString(digest[:])), nil
}
func checkpointRead04810(dir string) (checkpointManifest04810, map[string][]byte, error) {
	stat, err := os.Lstat(dir)
	if err != nil {
		return checkpointManifest04810{}, nil, err
	}
	if !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 {
		return checkpointManifest04810{}, nil, errors.New("unsafe checkpoint directory")
	}
	meta, err := os.Lstat(filepath.Join(dir, "checkpoint.json"))
	if err != nil {
		return checkpointManifest04810{}, nil, err
	}
	if !meta.Mode().IsRegular() || meta.Size() > 65536 {
		return checkpointManifest04810{}, nil, errors.New("invalid checkpoint manifest")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "checkpoint.json"))
	if err != nil {
		return checkpointManifest04810{}, nil, err
	}
	var index checkpointManifest04810
	if err = json.Unmarshal(raw, &index); err != nil {
		return index, nil, err
	}
	if index.Format != 1 || len(index.Files) > checkpointMaxFiles04810 || (index.Absent && len(index.Files) != 0) {
		return index, nil, errors.New("invalid state checkpoint inventory")
	}
	contents := map[string][]byte{}
	var total int
	for _, entry := range index.Files {
		if !checkpointFile04810.MatchString(entry.Name) || len(entry.SHA256) != 64 {
			return index, nil, errors.New("invalid checkpoint member")
		}
		if _, ok := contents[entry.Name]; ok {
			return index, nil, errors.New("duplicate checkpoint member")
		}
		name := filepath.Join(dir, entry.Name)
		st, err := os.Lstat(name)
		if err != nil {
			return index, nil, err
		}
		if !st.Mode().IsRegular() || st.Size() > runtimeValueLimit0303 {
			return index, nil, errors.New("unsafe checkpoint member")
		}
		body, err := os.ReadFile(name)
		if err != nil {
			return index, nil, err
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != entry.SHA256 || !json.Valid(body) {
			return index, nil, errors.New("checkpoint checksum mismatch or invalid JSON")
		}
		total += len(body)
		if total > checkpointMaxBytes04810 {
			return index, nil, errors.New("checkpoint exceeds runtime quota")
		}
		contents[entry.Name] = body
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return index, nil, err
	}
	if len(entries) != len(contents)+1 {
		return index, nil, errors.New("unexpected checkpoint members")
	}
	return index, contents, nil
}
func checkpointWrite04810(path string, body []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(body); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

func (s *Supervisor) SnapshotRuntimeState04810(ctx context.Context, key Key, txID string) error {
	if s == nil {
		return errors.New("extension supervisor is unavailable")
	}
	s.runtimeMu0303.Lock()
	defer s.runtimeMu0303.Unlock()
	return snapshotRuntime04810(ctx, s.cfg.ExtensionRoot, key, txID)
}
func snapshotRuntime04810(ctx context.Context, root string, key Key, txID string) error {
	path, err := checkpointPath04810(root, key, txID)
	if err != nil {
		return err
	}
	source := runtimeDir0303(root, key)
	// Refuse a symlinked runtime-data parent even if the state leaf itself
	// appears to be a regular directory through that symlink.
	if err = secureDirectory0303(filepath.Dir(source)); err != nil {
		return err
	}
	// Existing complete snapshots are immutable, allowing deterministic retries.
	if _, err := os.Lstat(path); err == nil {
		_, _, err = checkpointRead04810(path)
		return err
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(path)
	if err = secureDirectory0303(parent); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(parent, ".checkpoint-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err = os.Chmod(tmp, 0700); err != nil {
		return err
	}
	index := checkpointManifest04810{Format: 1, Files: []checkpointFileEntry04810{}}
	stat, err := os.Lstat(source)
	if errors.Is(err, os.ErrNotExist) {
		index.Absent = true
	} else if err != nil {
		return err
	} else if !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe runtime state directory")
	} else {
		entries, err := os.ReadDir(source)
		if err != nil {
			return err
		}
		var total int64
		for _, item := range entries {
			if err = ctx.Err(); err != nil {
				return err
			}
			if !checkpointFile04810.MatchString(item.Name()) {
				return fmt.Errorf("unexpected runtime state file %q", item.Name())
			}
			st, err := os.Lstat(filepath.Join(source, item.Name()))
			if err != nil {
				return err
			}
			if !st.Mode().IsRegular() || st.Size() > runtimeValueLimit0303 {
				return errors.New("unsafe runtime state member")
			}
			total += st.Size()
			if total > checkpointMaxBytes04810 || len(index.Files) >= checkpointMaxFiles04810 {
				return errors.New("runtime state quota exceeded")
			}
			body, err := os.ReadFile(filepath.Join(source, item.Name()))
			if err != nil {
				return err
			}
			if len(body) > runtimeValueLimit0303 || !json.Valid(body) {
				return errors.New("invalid runtime state JSON")
			}
			sum := sha256.Sum256(body)
			if err = checkpointWrite04810(filepath.Join(tmp, item.Name()), body); err != nil {
				return err
			}
			index.Files = append(index.Files, checkpointFileEntry04810{Name: item.Name(), SHA256: hex.EncodeToString(sum[:])})
		}
	}
	manifest, err := json.Marshal(index)
	if err != nil {
		return err
	}
	if err = checkpointWrite04810(filepath.Join(tmp, "checkpoint.json"), manifest); err != nil {
		return err
	}
	syncRuntimeDirectory0303(tmp)
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	syncRuntimeDirectory0303(parent)
	return nil
}

func (s *Supervisor) RestoreRuntimeState04810(ctx context.Context, key Key, txID string) error {
	if s == nil {
		return errors.New("extension supervisor is unavailable")
	}
	s.runtimeMu0303.Lock()
	defer s.runtimeMu0303.Unlock()
	return restoreRuntime04810(ctx, s.cfg.ExtensionRoot, key, txID)
}
func restoreRuntime04810(ctx context.Context, root string, key Key, txID string) error {
	path, err := checkpointPath04810(root, key, txID)
	if err != nil {
		return err
	}
	index, files, err := checkpointRead04810(path)
	if err != nil {
		return fmt.Errorf("checkpoint validation refused restore: %w", err)
	}
	dest := runtimeDir0303(root, key)
	parent := filepath.Dir(dest)
	if err = secureDirectory0303(parent); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(parent, ".restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	for name, body := range files {
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = checkpointWrite04810(filepath.Join(staging, name), body); err != nil {
			return err
		}
	}
	syncRuntimeDirectory0303(staging)
	old, err := os.MkdirTemp(parent, ".previous-")
	if err != nil {
		return err
	}
	if err = os.Remove(old); err != nil {
		return err
	}
	st, err := os.Lstat(dest)
	oldExists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if oldExists {
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe runtime state directory")
		}
		if err = os.Rename(dest, old); err != nil {
			return err
		}
	}
	if !index.Absent {
		if err = os.Rename(staging, dest); err != nil {
			if oldExists {
				_ = os.Rename(old, dest)
			}
			return err
		}
	}
	syncRuntimeDirectory0303(parent)
	if oldExists {
		return os.RemoveAll(old)
	}
	return nil
}

func (s *Supervisor) DiscardRuntimeState04810(ctx context.Context, key Key, txID string) error {
	if s == nil {
		return errors.New("extension supervisor is unavailable")
	}
	path, err := checkpointPath04810(s.cfg.ExtensionRoot, key, txID)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if !strings.HasPrefix(filepath.Base(filepath.Dir(path)), "extupd-") {
		return errors.New("invalid checkpoint location")
	}
	return os.RemoveAll(path)
}
