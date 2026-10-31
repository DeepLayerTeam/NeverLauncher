package main

// Game-world backups are deliberately independent of Backend/PostgreSQL backups.
// The only supported live-server consistency policy is a confirmed graceful
// stop through Host Supervisor (which sends the Minecraft `stop` command).
// Files are copied only after the game has stopped; no unacknowledged save-all
// is ever treated as a consistent online snapshot.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const worldBackupSchema02810 = "launcher-world-backup/v1"

var worldBackupID02810 = regexp.MustCompile(`^[0-9a-f]{32}$`)

type worldBackupEntry02810 struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}
type worldBackupManifest02810 struct {
	Schema      string                  `json:"schema"`
	ID          string                  `json:"id"`
	CreatedAt   string                  `json:"createdAt"`
	Consistency string                  `json:"consistency"`
	Platform    string                  `json:"platform,omitempty"`
	Worlds      []string                `json:"worlds"`
	TotalBytes  int64                   `json:"totalBytes"`
	Entries     []worldBackupEntry02810 `json:"entries"`
}
type worldBackupLock02810 struct {
	PID      int    `json:"pid"`
	Identity string `json:"identity"`
	Nonce    string `json:"nonce"`
}

func worldBackupHandle02810(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: nl server-bridge host world-backup create|verify|restore|list [--server-root PATH] [--backup-root PATH]")
	}
	action := args[0]
	args = args[1:]
	root, err := canonicalServerRoot0199(flagValue(args, "--server-root", "."))
	if err != nil {
		return err
	}
	dir, err := worldBackupLocation02810(root, flagValue(args, "--backup-root", ""))
	if err != nil {
		return err
	}
	if action == "list" {
		return worldBackupList02810(dir, flagValue(args, "--output", ""))
	}
	if action == "gate-recover" {
		if flagValue(args, "--confirm", "") != "stale-gate" {
			return errors.New("gate-recover requires --confirm stale-gate; reconcile Host Supervisor/JVM first")
		}
		return worldBackupHostGateRecover04110(root)
	}
	if action != "create" && action != "verify" && action != "restore" {
		return fmt.Errorf("unknown world-backup operation %q", action)
	}
	if err = worldBackupPrivateDir02810(dir); err != nil {
		return err
	}
	release, err := worldBackupLockAcquire02810(dir)
	if err != nil {
		return err
	}
	defer release()
	var m worldBackupManifest02810
	switch action {
	case "create":
		policy := strings.TrimSpace(flagValue(args, "--consistency", "stopped"))
		if policy != "stopped" && policy != "stop" {
			return errors.New("--consistency must be stopped or stop")
		}
		worlds := multiFlagValues01910(args, "--world")
		// Validate the selection before stopping a live server.
		candidates, checkErr := worldBackupWorlds02810(root, worlds)
		if checkErr != nil {
			return checkErr
		}
		if _, checkErr = worldBackupSources02810(root, candidates); checkErr != nil {
			return checkErr
		}
		// Serialize the *entire* quiesce and copy interval against every JVM
		// spawn (including crash-loop restarts) using an atomic host gate.
		// The gate is acquired before observing host state so a new supervisor
		// cannot enter after the stopped-state check.
		releaseGate, gateErr := worldBackupHostGateAcquire04110(root, "backup")
		if gateErr != nil {
			return gateErr
		}
		defer releaseGate()
		if err = worldBackupQuiesce02810(root, policy); err != nil {
			return err
		}
		m, err = worldBackupCreate02810(root, dir, worlds, policy)
	case "verify", "restore":
		id := flagValue(args, "--id", "")
		if !worldBackupID02810.MatchString(id) {
			return errors.New("--id must be a 32-character hexadecimal backup ID")
		}
		m, err = worldBackupVerify02810(filepath.Join(dir, id))
		if err != nil {
			return err
		}
		if action == "restore" {
			dest := flagValue(args, "--destination", "")
			if dest == "" {
				return errors.New("restore requires --destination (new, non-existing directory)")
			}
			if flagValue(args, "--confirm", "") != id {
				return errors.New("restore requires --confirm matching the backup ID")
			}
			if err = worldBackupRestore02810(root, dir, m, filepath.Join(dir, id), dest); err != nil {
				return err
			}
		}
	}
	if err != nil {
		return err
	}
	return writeOrPrintJSON(flagValue(args, "--output", ""), map[string]any{"schema": worldBackupSchema02810, "action": action, "backupRoot": dir, "manifest": m})
}

func worldBackupLocation02810(root, requested string) (string, error) {
	if requested == "" {
		hash := sha256.Sum256([]byte(root))
		requested = filepath.Join(filepath.Dir(root), "."+filepath.Base(root)+"-world-backups-"+hex.EncodeToString(hash[:4]))
	}
	abs, err := filepath.Abs(requested)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	if err = worldBackupDisjoint02810(root, abs); err != nil {
		return "", err
	}
	// Disallow symlink traversal along the backup storage path, including ancestors.
	if err = worldBackupNoSymlinkAncestors02810(abs); err != nil {
		return "", err
	}
	return abs, nil
}
func worldBackupDisjoint02810(a, b string) error {
	for _, pair := range [][2]string{{a, b}, {b, a}} {
		rel, err := filepath.Rel(pair[0], pair[1])
		if err != nil {
			return err
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return errors.New("world backup paths must not overlap server root, backup store, or restore destination")
		}
	}
	return nil
}
func worldBackupNoSymlinkAncestors02810(path string) error {
	path = filepath.Clean(path)
	for {
		fi, err := os.Lstat(path)
		if err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("symlink in path: %s", path)
			}
			if !fi.IsDir() {
				return fmt.Errorf("not a directory: %s", path)
			}
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		parent := filepath.Dir(path)
		if parent == path {
			break
		}
		path = parent
	}
	return nil
}
func worldBackupPrivateDir02810(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode().Perm()&0077 != 0 {
		return errors.New("world backup directory must be a private non-symlink directory (0700)")
	}
	return nil
}
func worldBackupRandom02810() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func worldBackupLockAcquire02810(dir string) (func(), error) {
	identity := hostOwnIdentity0282()
	if identity == "" {
		return nil, errors.New("backup requires verifiable host process identity")
	}
	nonce, err := worldBackupRandom02810()
	if err != nil {
		return nil, err
	}
	own := worldBackupLock02810{PID: os.Getpid(), Identity: identity, Nonce: nonce}
	path := filepath.Join(dir, "operation.lock")
	data, _ := json.Marshal(own)
	for tries := 0; tries < 3; tries++ {
		f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e == nil {
			_, e = f.Write(data)
			if e == nil {
				e = f.Sync()
			}
			ce := f.Close()
			if e == nil {
				e = ce
			}
			if e != nil {
				_ = os.Remove(path)
				return nil, e
			}
			return func() {
				var cur worldBackupLock02810
				if worldBackupReadJSON02810(path, &cur) == nil && cur == own {
					_ = os.Remove(path)
				}
			}, nil
		}
		if !errors.Is(e, os.ErrExist) {
			return nil, e
		}
		fi, e := os.Lstat(path)
		if e != nil {
			return nil, e
		}
		if !fi.Mode().IsRegular() {
			return nil, errors.New("world backup lock is not a regular file")
		}
		var existing worldBackupLock02810
		if err := worldBackupReadJSON02810(path, &existing); err != nil {
			return nil, err
		}
		if existing.Identity == "" || hostIdentityMatches0282(existing.PID, existing.Identity) {
			return nil, errors.New("world backup operation already in progress or unverifiable lock owner")
		}
		stale := path + ".stale-" + nonce
		if err := os.Rename(path, stale); err != nil {
			return nil, err
		}
		_ = os.Remove(stale)
	}
	return nil, errors.New("world backup lock contention")
}
func worldBackupReadJSON02810(path string, v any) error {
	check, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !check.Mode().IsRegular() {
		return errors.New("backup metadata must be a real regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err == nil && !os.SameFile(check, fi) {
		return errors.New("backup metadata changed during open")
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || fi.Size() > 32<<20 {
		return errors.New("invalid backup metadata file")
	}
	dec := json.NewDecoder(io.LimitReader(f, 32<<20))
	dec.DisallowUnknownFields()
	if err = dec.Decode(v); err != nil {
		return err
	}
	if dec.Decode(new(any)) != io.EOF {
		return errors.New("trailing backup metadata")
	}
	return nil
}
func worldBackupQuiesce02810(root, policy string) error {
	paths := hostPaths01910(root)
	state, err := readServerBridgeHostRuntime01910(paths["runtime"])
	if errors.Is(err, os.ErrNotExist) {
		// Absence of runtime.json is not proof of an idle host: a supervisor
		// might hold the lock while preparing its first child process.
		lock, lockErr := readServerBridgeHostLock01910(paths["lock"])
		if lockErr == nil {
			if lock.Identity == "" || hostIdentityMatches0282(lock.PID, lock.Identity) || updaterProcessAlive0156(lock.PID) {
				return errors.New("Host supervisor lock exists without runtime; backup unsafe")
			}
		} else if !errors.Is(lockErr, os.ErrNotExist) {
			return fmt.Errorf("cannot check Host supervisor lock: %w", lockErr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot establish host state: %w", err)
	}
	if state.ProcessPID > 0 {
		if !hostIdentityMatches0282(state.ProcessPID, state.ProcessIdentity) {
			return errors.New("unverified/stale Minecraft PID; reconcile before world backup")
		}
		if policy != "stop" {
			return errors.New("Minecraft is running: use --consistency stop for supervised graceful stop")
		}
		stopResult := filepath.Join(paths["dir"], "world-backup-stop-result.json")
		defer os.Remove(stopResult)
		if err = stopServerBridgeHost01910([]string{"--server-root", root, "--output", stopResult}); err != nil {
			return err
		}
	}
	// The supervisor may still be exiting after reporting stopped. Wait for
	// the exact former identity to disappear; never silently race a restart.
	deadline := time.Now().Add(5 * time.Second)
	var current serverBridgeHostRuntime01910
	for {
		current, err = readServerBridgeHostRuntime01910(paths["runtime"])
		if err != nil {
			return err
		}
		if !hostIdentityMatches0282(current.SupervisorPID, current.SupervisorIdentity) || !time.Now().Before(deadline) {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if current.ProcessPID > 0 || hostIdentityMatches0282(current.ProcessPID, current.ProcessIdentity) {
		return errors.New("Minecraft process not confirmed stopped")
	}
	if current.Status == "starting" || current.Status == "running" || current.Status == "restarting" {
		return fmt.Errorf("unsafe host runtime state %s", current.Status)
	}
	if hostIdentityMatches0282(current.SupervisorPID, current.SupervisorIdentity) {
		return errors.New("supervisor is still running; cannot guarantee no restart during backup")
	}
	if current.Status == "crashed" || current.Status == "failed" || current.Status == "restarting" {
		return errors.New("crashed/failed world is not a confirmed consistent backup source")
	}
	if current.StopMethod == "kill" || current.StopMethod == "terminate" {
		return errors.New("last Minecraft shutdown was forced; world flush is unverified")
	}
	if current.Status == "stopped" && (current.StopMethod != "console-stop" || current.ExitCode == nil || *current.ExitCode != 0) {
		return errors.New("last Minecraft stop was not confirmed graceful")
	}
	if current.Status == "exited" && (current.ExitCode == nil || *current.ExitCode != 0) {
		return errors.New("last Minecraft exit was not clean")
	}
	if policy == "stop" && state.ProcessPID > 0 && (current.StopMethod != "console-stop" || current.ExitCode == nil || *current.ExitCode != 0) {
		return errors.New("Minecraft graceful shutdown was not confirmed; refusing world backup")
	}
	if lock, err := readServerBridgeHostLock01910(paths["lock"]); err == nil && (hostIdentityMatches0282(lock.PID, lock.Identity) || (lock.Identity == "" && updaterProcessAlive0156(lock.PID))) {
		return errors.New("live Host supervisor lock prevents consistent backup")
	}
	return nil
}
func worldBackupValidRelative02810(name string) bool {
	if name == "" || strings.Contains(name, "\\") || strings.ContainsRune(name, '\x00') || strings.Contains(name, ":") || filepath.IsAbs(name) {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(name)))
	return clean == name && clean != "." && clean != ".." && !strings.HasPrefix(clean, "../") && !strings.HasPrefix(clean, "/")
}
func worldBackupWorlds02810(root string, requested []string) ([]string, error) {
	if len(requested) == 0 {
		level := "world"
		b, err := os.ReadFile(filepath.Join(root, "server.properties"))
		if err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "level-name=") {
					level = strings.TrimSpace(strings.TrimPrefix(line, "level-name="))
					break
				}
			}
		}
		requested = []string{level}
		for _, name := range []string{level + "_nether", level + "_the_end"} {
			if fi, err := os.Lstat(filepath.Join(root, name)); err == nil && fi.IsDir() {
				requested = append(requested, name)
			}
		}
	}
	selected := map[string]bool{}
	worlds := []string{}
	for _, name := range requested {
		if !worldBackupValidRelative02810(name) || strings.Contains(name, "/") || name == ".launcher" {
			return nil, fmt.Errorf("invalid world directory %q", name)
		}
		if selected[name] {
			continue
		}
		selected[name] = true
		info, err := os.Lstat(filepath.Join(root, name))
		if err != nil {
			return nil, fmt.Errorf("world %s: %w", name, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("world %s must be a real directory", name)
		}
		worlds = append(worlds, name)
	}
	sort.Strings(worlds)
	return worlds, nil
}
func worldBackupSources02810(root string, worlds []string) ([]string, error) {
	sources := append([]string{}, worlds...)
	for _, name := range []string{"plugins", "config", "server.properties", "bukkit.yml", "spigot.yml", "paper.yml", "purpur.yml", "permissions.yml", "ops.json", "whitelist.json", "banned-players.json", "banned-ips.json", "velocity.toml", "waterfall.yml", "bungee.yml"} {
		if _, err := os.Lstat(filepath.Join(root, name)); err == nil {
			sources = append(sources, name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	// Refuse overlapping entries; otherwise the same file could be backed up twice.
	seen := map[string]bool{}
	for _, s := range sources {
		if seen[s] {
			return nil, fmt.Errorf("world %q overlaps configuration", s)
		}
		seen[s] = true
	}
	sort.Strings(sources)
	return sources, nil
}
func worldBackupCollect02810(root string, sources []string) ([]worldBackupEntry02810, error) {
	entries := []worldBackupEntry02810{}
	for _, name := range sources {
		err := filepath.WalkDir(filepath.Join(root, name), func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if !worldBackupValidRelative02810(rel) {
				return fmt.Errorf("invalid relative source path %s", rel)
			}
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			ent := worldBackupEntry02810{Path: rel, Mode: uint32(info.Mode().Perm())}
			if info.IsDir() {
				ent.Type = "dir"
			} else if info.Mode().IsRegular() {
				ent.Type = "file"
				ent.Size = info.Size()
			} else {
				return fmt.Errorf("unsafe world backup entry: %s (symlink or special file)", rel)
			}
			entries = append(entries, ent)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	if len(entries) == 0 {
		return nil, errors.New("backup selection is empty")
	}
	return entries, nil
}
func worldBackupCopy02810(src, dst string, expectedSize int64, mode fs.FileMode) (string, error) {
	info, err := os.Lstat(src)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() != expectedSize {
		return "", fmt.Errorf("source changed: %s", src)
	}
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	openInfo, err := in.Stat()
	if err != nil || !os.SameFile(info, openInfo) {
		return "", errors.New("source file changed during open")
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode.Perm())
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(out, hasher), in)
	if copyErr == nil && n != expectedSize {
		copyErr = errors.New("source size changed during copy")
	}
	if copyErr == nil {
		copyErr = out.Sync()
	}
	closeErr := out.Close()
	if copyErr == nil {
		copyErr = closeErr
	}
	after, statErr := in.Stat()
	if copyErr == nil && (statErr != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime())) {
		copyErr = errors.New("source modified during backup")
	}
	if copyErr != nil {
		_ = os.Remove(dst)
		return "", copyErr
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
func worldBackupWriteManifest02810(path string, m worldBackupManifest02810) error {
	// Manifest is the commit marker; before it is written payload remains partial.
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	c := f.Close()
	if err != nil {
		return err
	}
	return c
}
func worldBackupSyncDir02810(dir string) error {
	// Windows does not support syncing directory handles through os.File.Sync;
	// individual payload files and manifest are flushed before rename.
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func worldBackupCreate02810(root, dir string, requested []string, policy string) (worldBackupManifest02810, error) {
	var empty worldBackupManifest02810
	worlds, err := worldBackupWorlds02810(root, requested)
	if err != nil {
		return empty, err
	}
	sources, err := worldBackupSources02810(root, worlds)
	if err != nil {
		return empty, err
	}
	entries, err := worldBackupCollect02810(root, sources)
	if err != nil {
		return empty, err
	}
	id, err := worldBackupRandom02810()
	if err != nil {
		return empty, err
	}
	stage := filepath.Join(dir, ".partial-"+id)
	if err = os.Mkdir(stage, 0700); err != nil {
		return empty, err
	}
	defer os.RemoveAll(stage)
	payload := filepath.Join(stage, "payload")
	if err = os.Mkdir(payload, 0700); err != nil {
		return empty, err
	}
	platform := "unknown"
	if cfg, readErr := readServerBridgeHostConfig01910(hostPaths01910(root)["config"]); readErr == nil {
		platform = cfg.Platform
	}
	m := worldBackupManifest02810{Schema: worldBackupSchema02810, ID: id, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Consistency: "confirmed-stopped", Platform: platform, Worlds: worlds, Entries: entries}
	for i := range m.Entries {
		ent := &m.Entries[i]
		dst := filepath.Join(payload, filepath.FromSlash(ent.Path))
		if ent.Type == "dir" {
			if err = os.Mkdir(dst, 0700); err != nil {
				return empty, err
			}
			continue
		}
		digest, copyErr := worldBackupCopy02810(filepath.Join(root, filepath.FromSlash(ent.Path)), dst, ent.Size, 0600)
		if copyErr != nil {
			return empty, copyErr
		}
		ent.SHA256 = digest
		m.TotalBytes += ent.Size
	}
	// Prove the persisted payload is complete before publishing the manifest.
	if err = worldBackupWriteManifest02810(filepath.Join(stage, "manifest.json"), m); err != nil {
		return empty, err
	}
	if _, err = worldBackupVerify02810(stage); err != nil {
		return empty, err
	}
	if err = worldBackupSyncDir02810(payload); err != nil {
		return empty, err
	}
	if err = worldBackupSyncDir02810(stage); err != nil {
		return empty, err
	}
	if err = os.Rename(stage, filepath.Join(dir, id)); err != nil {
		return empty, err
	}
	if err = worldBackupSyncDir02810(dir); err != nil {
		return m, fmt.Errorf("backup published but directory sync failed; inspect ID %s: %w", id, err)
	}
	return m, nil
}
func worldBackupManifestValid02810(m worldBackupManifest02810) error {
	if m.Schema != worldBackupSchema02810 || !worldBackupID02810.MatchString(m.ID) || m.Consistency != "confirmed-stopped" || len(m.Worlds) == 0 || len(m.Entries) == 0 || len(m.Entries) > 1000000 {
		return errors.New("invalid world backup manifest")
	}
	found := map[string]string{}
	worlds := map[string]bool{}
	var total int64
	for _, w := range m.Worlds {
		if !worldBackupValidRelative02810(w) || strings.Contains(w, "/") || worlds[w] {
			return errors.New("invalid world selection")
		}
		worlds[w] = true
	}
	for _, e := range m.Entries {
		if !worldBackupValidRelative02810(e.Path) || found[e.Path] != "" || e.Mode > 0777 {
			return fmt.Errorf("invalid or duplicate manifest entry: %q", e.Path)
		}
		if e.Type != "dir" && e.Type != "file" {
			return errors.New("invalid backup entry type")
		}
		if e.Type == "dir" && (e.Size != 0 || e.SHA256 != "") {
			return errors.New("invalid directory metadata")
		}
		if e.Type == "file" && (e.Size < 0 || len(e.SHA256) != 64) {
			return errors.New("invalid file metadata")
		}
		if e.Type == "file" {
			if _, err := hex.DecodeString(e.SHA256); err != nil {
				return err
			}
			if total > int64(^uint64(0)>>1)-e.Size {
				return errors.New("backup size overflow")
			}
			total += e.Size
		}
		parent := e.Path
		for strings.Contains(parent, "/") {
			parent = parent[:strings.LastIndex(parent, "/")]
			if found[parent] == "file" {
				return errors.New("manifest path descends into file")
			}
		}
		found[e.Path] = e.Type
	}
	if total != m.TotalBytes {
		return errors.New("manifest byte count mismatch")
	}
	for w := range worlds {
		if found[w] != "dir" {
			return fmt.Errorf("missing world directory %s", w)
		}
	}
	for path := range found {
		if strings.Contains(path, "/") {
			parent := path[:strings.LastIndex(path, "/")]
			if found[parent] != "dir" {
				return errors.New("manifest missing parent directory")
			}
		}
	}
	return nil
}
func worldBackupVerify02810(dir string) (worldBackupManifest02810, error) {
	var m worldBackupManifest02810
	fi, err := os.Lstat(dir)
	if err != nil {
		return m, err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return m, errors.New("backup entry is not a real directory")
	}
	payloadInfo, err := os.Lstat(filepath.Join(dir, "payload"))
	if err != nil {
		return m, err
	}
	if !payloadInfo.IsDir() || payloadInfo.Mode()&os.ModeSymlink != 0 {
		return m, errors.New("backup payload is not a real directory")
	}
	if err := worldBackupReadJSON02810(filepath.Join(dir, "manifest.json"), &m); err != nil {
		return m, err
	}
	if err := worldBackupManifestValid02810(m); err != nil {
		return m, err
	}
	expected := map[string]worldBackupEntry02810{}
	for _, e := range m.Entries {
		expected[e.Path] = e
	}
	payload := filepath.Join(dir, "payload")
	count := 0
	err = filepath.WalkDir(payload, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == payload {
			return nil
		}
		rel, err := filepath.Rel(payload, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		e, ok := expected[rel]
		if !ok {
			return fmt.Errorf("unexpected backup payload entry %s", rel)
		}
		fi, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if e.Type == "dir" {
			if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("invalid backup directory %s", rel)
			}
		} else {
			if !fi.Mode().IsRegular() || fi.Size() != e.Size {
				return fmt.Errorf("invalid file size/type %s", rel)
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			h := sha256.New()
			n, err := io.Copy(h, f)
			_ = f.Close()
			if err != nil {
				return err
			}
			if n != e.Size || hex.EncodeToString(h.Sum(nil)) != e.SHA256 {
				return fmt.Errorf("checksum mismatch %s", rel)
			}
		}
		count++
		return nil
	})
	if err != nil {
		return m, err
	}
	if count != len(expected) {
		return m, errors.New("backup payload entries missing")
	}
	return m, nil
}
func worldBackupRestore02810(root, store string, m worldBackupManifest02810, source, dest string) error {
	abs, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	abs = filepath.Clean(abs)
	if err = worldBackupDisjoint02810(root, abs); err != nil {
		return err
	}
	if err = worldBackupDisjoint02810(store, abs); err != nil {
		return err
	}
	if err = worldBackupNoSymlinkAncestors02810(filepath.Dir(abs)); err != nil {
		return err
	}
	if _, err = os.Lstat(abs); err == nil {
		return errors.New("restore destination already exists; overwrite is forbidden")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(abs)
	if fi, err := os.Lstat(parent); err != nil || !fi.IsDir() {
		return errors.New("restore destination parent must already exist and be a real directory")
	}
	stage := filepath.Join(parent, "."+filepath.Base(abs)+".restore-"+m.ID)
	if err = os.Mkdir(stage, 0700); err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for _, e := range m.Entries {
		to := filepath.Join(stage, filepath.FromSlash(e.Path))
		from := filepath.Join(source, "payload", filepath.FromSlash(e.Path))
		if e.Type == "dir" {
			if err = os.Mkdir(to, 0700); err != nil {
				return err
			}
			continue
		}
		digest, copyErr := worldBackupCopy02810(from, to, e.Size, 0600)
		if copyErr != nil {
			return copyErr
		}
		if digest != e.SHA256 {
			return fmt.Errorf("restore checksum mismatch %s", e.Path)
		}
		if err = os.Chmod(to, os.FileMode(e.Mode)&0777); err != nil {
			return err
		}
	}
	// Apply directory modes bottom-up after files have been populated.
	for i := len(m.Entries) - 1; i >= 0; i-- {
		e := m.Entries[i]
		if e.Type == "dir" {
			if err = os.Chmod(filepath.Join(stage, filepath.FromSlash(e.Path)), os.FileMode(e.Mode)&0777); err != nil {
				return err
			}
		}
	}
	// Restored payload is independently checked before the atomic publication.
	for _, e := range m.Entries {
		if e.Type != "file" {
			continue
		}
		f, openErr := os.Open(filepath.Join(stage, filepath.FromSlash(e.Path)))
		if openErr != nil {
			return openErr
		}
		h := sha256.New()
		_, readErr := io.Copy(h, f)
		_ = f.Close()
		if readErr != nil {
			return readErr
		}
		if hex.EncodeToString(h.Sum(nil)) != e.SHA256 {
			return errors.New("restored payload failed verification")
		}
	}
	if err = worldBackupSyncDir02810(stage); err != nil {
		return err
	}
	if err = os.Rename(stage, abs); err != nil {
		return err
	}
	return worldBackupSyncDir02810(parent)
}
func worldBackupList02810(dir, output string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return writeOrPrintJSON(output, map[string]any{"schema": worldBackupSchema02810, "backups": []any{}})
	}
	if err != nil {
		return err
	}
	backups := []worldBackupManifest02810{}
	for _, e := range entries {
		if !e.IsDir() || !worldBackupID02810.MatchString(e.Name()) {
			continue
		}
		var m worldBackupManifest02810
		if worldBackupReadJSON02810(filepath.Join(dir, e.Name(), "manifest.json"), &m) == nil && m.ID == e.Name() && worldBackupManifestValid02810(m) == nil {
			backups = append(backups, m)
		}
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].CreatedAt > backups[j].CreatedAt })
	return writeOrPrintJSON(output, map[string]any{"schema": worldBackupSchema02810, "backupRoot": dir, "backups": backups})
}
