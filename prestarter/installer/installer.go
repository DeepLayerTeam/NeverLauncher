package installer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	prestarter "github.com/DeepLayerTeam/Launcher/prestarter"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Options struct {
	Root, Bundle, TrustedKey string
	Offline, NoStart         bool
}
type record struct {
	Generation                      uint64 `json:"generation"`
	Release, ConfigHash, BinaryHash string
	Offline                         bool
}
type installation struct{ root, base, key string }

func binaryName() string {
	if runtime.GOOS == "windows" {
		return "neverprestarter.exe"
	}
	return "neverprestarter"
}
func digest(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func regular(path string, limit int64) ([]byte, error) {
	st, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Size() > limit {
		return nil, errors.New("unsafe or oversized regular file")
	}
	return os.ReadFile(path)
}
func verifyFile(path string, a prestarter.Artifact) error {
	st, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() || st.Size() != a.Size {
		return errors.New("unexpected file size or type")
	}
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, a.Size+1))
	if e != nil || n != a.Size || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		return errors.New("SHA-256 mismatch")
	}
	return nil
}
func secureDir(dir string) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	for p := dir; ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil {
			return e
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink in managed installation path")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}
func copyFile(src, dst string, mode os.FileMode) error {
	f, e := os.Open(src)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = secureDir(filepath.Dir(dst)); e != nil {
		return e
	}
	out, e := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if e != nil {
		return e
	}
	if _, e = io.Copy(out, f); e != nil {
		out.Close()
		return e
	}
	if e = out.Sync(); e != nil {
		out.Close()
		return e
	}
	return out.Close()
}
func atomicWrite(path string, data []byte) error {
	if e := secureDir(filepath.Dir(path)); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".write-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(data); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	// On POSIX persist the rename itself, not only the temporary file.
	return syncParent(path)
}
func verifyBundleConfig02312(dir string, raw []byte, rootKey string) (prestarter.Config, string, error) {
	var env prestarter.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return prestarter.Config{}, "", err
	}
	if env.SchemaVersion != "2.0" {
		return prestarter.VerifyEnvelope(raw, rootKey)
	}
	policyBytes, err := regular(filepath.Join(dir, "trust-policy.signed.json"), 128*1024)
	if err != nil {
		return prestarter.Config{}, "", err
	}
	policy, _, err := prestarter.VerifyTrustPolicy(policyBytes, rootKey, time.Now().UTC())
	if err != nil {
		return prestarter.Config{}, "", err
	}
	return prestarter.VerifyEnvelopeWithPolicy(raw, rootKey, &policy)
}
func verifyInstalledPolicy02312(dir string, raw []byte, key string) error {
	_, _, err := verifyBundleConfig02312(dir, raw, key)
	return err
}
func copyPolicy02312(src, dst string, raw []byte) error {
	var env prestarter.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return err
	}
	if env.SchemaVersion != "2.0" {
		return nil
	}
	bytes, err := regular(filepath.Join(src, "trust-policy.signed.json"), 128*1024)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dst, "trust-policy.signed.json"), bytes)
}
func VerifyBundle(bundle, key string, offline bool) (prestarter.Config, string, error) {
	var empty prestarter.Config
	if !filepath.IsAbs(bundle) {
		return empty, "", errors.New("bundle must be absolute")
	}
	path := filepath.Clean(bundle)
	real, e := filepath.EvalSymlinks(path)
	if e != nil || real != path {
		return empty, "", errors.New("missing or symlinked bundle")
	}
	raw, e := regular(filepath.Join(path, "bootstrap.signed.json"), 1024*1024)
	if e != nil {
		return empty, "", e
	}
	cfg, id, e := verifyBundleConfig02312(path, raw, key)
	if e != nil {
		return empty, "", e
	}
	if _, e = cfg.SelectTarget(); e != nil {
		return empty, "", e
	}
	art, e := cfg.InstallerFor(runtime.GOOS, runtime.GOARCH)
	if e != nil {
		return empty, "", e
	}
	if e = verifyFile(filepath.Join(path, binaryName()), art); e != nil {
		return empty, "", fmt.Errorf("signed Prestarter: %w", e)
	}
	if offline {
		if e = verifyOffline(path, cfg); e != nil {
			return empty, "", e
		}
	}
	return cfg, id, nil
}
func verifyOffline(dir string, cfg prestarter.Config) error {
	target, e := cfg.SelectTarget()
	if e != nil {
		return e
	}
	for _, a := range append(append([]prestarter.Component{}, target.Components...), prestarter.Component{Name: "manifest", Artifact: cfg.Manifest}) {
		if e = verifyFile(filepath.Join(dir, "objects", a.SHA256), a.Artifact); e != nil {
			return fmt.Errorf("offline %s: %w", a.Name, e)
		}
	}
	if e = verifyFile(filepath.Join(dir, "managed-jre", "manifest.json"), cfg.JavaManifest); e != nil {
		return fmt.Errorf("offline Java manifest: %w", e)
	}
	return nil
}
func newInstall(opts Options) (*installation, error) {
	if opts.TrustedKey == "" {
		return nil, errors.New("embedded trust root required")
	}
	if !filepath.IsAbs(opts.Root) {
		return nil, errors.New("absolute root required")
	}
	root := filepath.Clean(opts.Root)
	if e := secureDir(root); e != nil {
		return nil, e
	}
	return &installation{root: root, base: filepath.Join(root, ".launcher-installer"), key: opts.TrustedKey}, nil
}
func (i *installation) current() (*record, error) {
	var result *record
	for _, slot := range []string{"active-0.json", "active-1.json"} {
		buf, e := regular(filepath.Join(i.base, slot), 16384)
		if e != nil {
			continue
		}
		var r record
		if json.Unmarshal(buf, &r) != nil || r.Release == "" || strings.ContainsAny(r.Release, "/\\") || strings.Contains(r.Release, "..") || len(r.ConfigHash) != 64 || len(r.BinaryHash) != 64 {
			continue
		}
		releaseDir := filepath.Join(i.base, "releases", r.Release)
		raw, e := regular(filepath.Join(releaseDir, "bootstrap.signed.json"), 1024*1024)
		if e != nil || digest(raw) != r.ConfigHash {
			continue
		}
		cfg, id, e := verifyBundleConfig02312(releaseDir, raw, i.key)
		if e != nil || id+"-"+runtime.GOOS+"-"+runtime.GOARCH != r.Release {
			continue
		}
		art, e := cfg.InstallerFor(runtime.GOOS, runtime.GOARCH)
		if e != nil || art.SHA256 != r.BinaryHash || verifyFile(filepath.Join(releaseDir, binaryName()), art) != nil {
			continue
		}
		if r.Offline && verifyOffline(filepath.Join(i.base, "offline", r.Release), cfg) != nil {
			continue
		}
		if result == nil || r.Generation > result.Generation {
			v := r
			result = &v
		}
	}
	if result == nil {
		return nil, errors.New("no verified installed release")
	}
	return result, nil
}
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		info, e := os.Lstat(path)
		if e != nil {
			return e
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink in offline bundle")
		}
		rel, e := filepath.Rel(src, path)
		if e != nil {
			return e
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return secureDir(target)
		}
		if !info.Mode().IsRegular() || info.Size() > 3<<30 {
			return errors.New("unsupported offline entry")
		}
		return copyFile(path, target, 0600)
	})
}
func (i *installation) store(bundle string, cfg prestarter.Config, id string, offline bool) (record, error) {
	rec := record{Release: id + "-" + runtime.GOOS + "-" + runtime.GOARCH, Offline: offline}
	raw, e := regular(filepath.Join(bundle, "bootstrap.signed.json"), 1024*1024)
	if e != nil {
		return rec, e
	}
	rec.ConfigHash = digest(raw)
	art, e := cfg.InstallerFor(runtime.GOOS, runtime.GOARCH)
	if e != nil {
		return rec, e
	}
	rec.BinaryHash = art.SHA256
	base := filepath.Join(i.base, "releases")
	if e = secureDir(base); e != nil {
		return rec, e
	}
	release := filepath.Join(base, rec.Release)
	if _, e = os.Lstat(release); errors.Is(e, os.ErrNotExist) {
		stage, err := os.MkdirTemp(base, ".incomplete-")
		if err != nil {
			return rec, err
		}
		defer os.RemoveAll(stage)
		if err = copyFile(filepath.Join(bundle, binaryName()), filepath.Join(stage, binaryName()), 0700); err != nil {
			return rec, err
		}
		if err = atomicWrite(filepath.Join(stage, "bootstrap.signed.json"), raw); err != nil {
			return rec, err
		}
		if e = copyPolicy02312(bundle, stage, raw); e != nil {
			return rec, e
		}
		if err = verifyFile(filepath.Join(stage, binaryName()), art); err != nil {
			return rec, err
		}
		if err = os.Rename(stage, release); err != nil {
			return rec, err
		}
	} else if e != nil {
		return rec, e
	}
	installedRaw, installedErr := regular(filepath.Join(release, "bootstrap.signed.json"), 1024*1024)
	if verifyFile(filepath.Join(release, binaryName()), art) != nil || installedErr != nil || digest(installedRaw) != rec.ConfigHash || verifyInstalledPolicy02312(release, installedRaw, i.key) != nil {
		// A matching signed bundle can repair a damaged release without
		// ever executing the damaged binary. Never delete the old directory.
		quarantine := release + ".broken-" + strconv.FormatInt(time.Now().UnixNano(), 10)
		if e = os.Rename(release, quarantine); e != nil {
			return rec, e
		}
		stage, err := os.MkdirTemp(base, ".incomplete-")
		if err != nil {
			return rec, err
		}
		defer os.RemoveAll(stage)
		if err = copyFile(filepath.Join(bundle, binaryName()), filepath.Join(stage, binaryName()), 0700); err != nil {
			return rec, err
		}
		if err = atomicWrite(filepath.Join(stage, "bootstrap.signed.json"), raw); err != nil {
			return rec, err
		}
		if e = copyPolicy02312(bundle, stage, raw); e != nil {
			return rec, e
		}
		if err = verifyFile(filepath.Join(stage, binaryName()), art); err != nil {
			return rec, err
		}
		if err = os.Rename(stage, release); err != nil {
			return rec, err
		}
	}
	installedRaw, e = regular(filepath.Join(release, "bootstrap.signed.json"), 1024*1024)
	if e != nil || digest(installedRaw) != rec.ConfigHash {
		return rec, errors.New("installed signed config corrupted")
	}
	if offline {
		offlineBase := filepath.Join(i.base, "offline")
		if e = secureDir(offlineBase); e != nil {
			return rec, e
		}
		folder := filepath.Join(offlineBase, rec.Release)
		if verifyOffline(folder, cfg) != nil {
			stage, err := os.MkdirTemp(offlineBase, ".incomplete-")
			if err != nil {
				return rec, err
			}
			defer os.RemoveAll(stage)
			if err = copyTree(bundle, stage); err != nil {
				return rec, err
			}
			if err = verifyOffline(stage, cfg); err != nil {
				return rec, err
			}
			if _, err = os.Lstat(folder); err == nil {
				if err = os.RemoveAll(folder); err != nil {
					return rec, err
				}
			}
			if err = os.Rename(stage, folder); err != nil {
				return rec, err
			}
		}
	}
	return rec, nil
}
func (i *installation) provision(ctx context.Context, r record, noStart bool) error {
	dir := filepath.Join(i.base, "releases", r.Release)
	config := filepath.Join(dir, "bootstrap.signed.json")
	raw, e := regular(config, 1024*1024)
	if e != nil || digest(raw) != r.ConfigHash {
		return errors.New("signed config damaged")
	}
	cfg, _, e := verifyBundleConfig02312(dir, raw, i.key)
	if e != nil {
		return e
	}
	art, e := cfg.InstallerFor(runtime.GOOS, runtime.GOARCH)
	if e != nil {
		return e
	}
	exe := filepath.Join(dir, binaryName())
	if e = verifyFile(exe, art); e != nil {
		return e
	}
	args := []string{"--config", config, "--root", i.root}
	if _, err := os.Stat(filepath.Join(dir, "trust-policy.signed.json")); err == nil {
		args = append(args, "--trust-policy", filepath.Join(dir, "trust-policy.signed.json"))
	}
	if r.Offline {
		args = append(args, "--offline", "--offline-dir", filepath.Join(i.base, "offline", r.Release))
	}
	if noStart {
		args = append(args, "--no-desktop")
	}
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if e = cmd.Run(); e != nil {
		return fmt.Errorf("Prestarter failed: %w", e)
	}
	return nil
}
func Install(ctx context.Context, opts Options) error {
	i, e := newInstall(opts)
	if e != nil {
		return e
	}
	if e = secureDir(i.base); e != nil {
		return e
	}
	lock, e := prestarter.AcquireInstallerLock(filepath.Join(i.base, "installer.lock"))
	if e != nil {
		return e
	}
	defer lock.Close()
	cfg, id, e := VerifyBundle(opts.Bundle, opts.TrustedKey, opts.Offline)
	if e != nil {
		return e
	}
	prev, _ := i.current()
	rec, e := i.store(opts.Bundle, cfg, id, opts.Offline)
	if e != nil {
		return e
	}
	rec.Generation = 1
	if prev != nil {
		rec.Generation = prev.Generation + 1
	}
	if rec.Generation == 0 {
		return errors.New("generation overflow")
	}
	// Provision first, commit second. The signed Prestarter may fail while
	// installing Managed Java or restoring the game. If the pointer were
	// advanced before that work, a power loss could leave an apparently
	// active but unusable release. Keep the previous verified pointer intact.
	if e = i.provision(ctx, rec, opts.NoStart); e != nil {
		return e
	}
	data, e := json.Marshal(rec)
	if e != nil {
		return e
	}
	if e = atomicWrite(filepath.Join(i.base, "active-"+strconv.FormatUint(rec.Generation%2, 10)+".json"), data); e != nil {
		return e
	}
	return i.createShortcut(rec, cfg)
}
func Repair(ctx context.Context, opts Options) error {
	i, e := newInstall(opts)
	if e != nil {
		return e
	}
	if e = secureDir(i.base); e != nil {
		return e
	}
	lock, e := prestarter.AcquireInstallerLock(filepath.Join(i.base, "installer.lock"))
	if e != nil {
		return e
	}
	rec, recErr := i.current()
	if recErr == nil {
		defer lock.Close()
		return i.provision(ctx, *rec, opts.NoStart)
	}
	// No runnable release exists: release the lock before calling Install.
	// First try the explicit signed bundle, then a retained offline source.
	lock.Close()
	if _, _, e = VerifyBundle(opts.Bundle, opts.TrustedKey, opts.Offline); e == nil {
		return Install(ctx, opts)
	}
	entries, _ := os.ReadDir(filepath.Join(i.base, "offline"))
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		candidate := filepath.Join(i.base, "offline", entry.Name())
		if _, _, verifyErr := VerifyBundle(candidate, opts.TrustedKey, true); verifyErr == nil {
			opts.Bundle = candidate
			opts.Offline = true
			return Install(ctx, opts)
		}
	}
	return fmt.Errorf("no verified repair source: %w", recErr)
}
func Uninstall(opts Options) error {
	i, e := newInstall(opts)
	if e != nil {
		return e
	}
	if e = i.removeShortcut(); e != nil {
		return e
	}
	if e = filepath.WalkDir(i.base, func(path string, d os.DirEntry, err error) error {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("unexpected symlink in installer directory")
		}
		return nil
	}); e != nil {
		return e
	}
	// Deliberately preserve root/launcher, root/profiles, Managed Java and saves.
	return os.RemoveAll(i.base)
}
