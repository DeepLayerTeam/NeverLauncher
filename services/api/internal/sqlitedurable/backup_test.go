package sqlitedurable

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOnlineBackupWALAndVerifiedRestore(t *testing.T) {
	opt := testOptions(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	store, err := Open(ctx, opt)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = store.Write(ctx, func(q Executor) error {
		if _, e := q.ExecContext(ctx, "CREATE TABLE snapshot_records(id INTEGER PRIMARY KEY, value TEXT NOT NULL)"); e != nil {
			return e
		}
		_, e := q.ExecContext(ctx, "INSERT INTO snapshot_records(id,value) VALUES(1,'committed WAL record')")
		return e
	}); err != nil {
		t.Fatal(err)
	}
	targetDir := filepath.Join(filepath.Dir(opt.Path), "backups")
	if err = os.Mkdir(targetDir, 0700); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(targetDir, "snapshot.db")
	// Concurrent writers stay enabled while VACUUM INTO reads its snapshot.
	var wg sync.WaitGroup
	wg.Add(1)
	errorsChan := make(chan error, 1)
	go func() {
		defer wg.Done()
		for i := 2; i < 70; i++ {
			if e := store.Write(ctx, func(q Executor) error {
				_, er := q.ExecContext(ctx, "INSERT INTO snapshot_records(id,value) VALUES(?,?)", i, "later")
				return er
			}); e != nil {
				errorsChan <- e
				return
			}
		}
	}()
	manifest, err := OnlineBackup(ctx, opt.Path, backup)
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	close(errorsChan)
	for e := range errorsChan {
		t.Fatal(e)
	}
	if manifest.SchemaVersion != 0 || manifest.Bytes <= 0 {
		t.Fatalf("unexpected snapshot metadata: %+v", manifest)
	}
	if _, err = VerifyBackup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	if _, err = OnlineBackup(ctx, opt.Path, backup); err == nil {
		t.Fatal("overwrote existing immutable backup")
	}
	restoreDir := filepath.Join(filepath.Dir(opt.Path), "restore")
	if err = os.Mkdir(restoreDir, 0700); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(restoreDir, "state.db")
	if _, err = RestoreBackup(ctx, backup, restored, false); err != nil {
		t.Fatal(err)
	}
	rs, err := Open(ctx, Options{Path: restored})
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	if err = rs.Read(ctx, func(q Executor) error {
		var v string
		if e := q.QueryRowContext(ctx, "SELECT value FROM snapshot_records WHERE id=1").Scan(&v); e != nil {
			return e
		}
		if v != "committed WAL record" {
			return errors.New("committed WAL record absent from online snapshot")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestBackupTamperingAndOfflineLock(t *testing.T) {
	opt := testOptions(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, err := Open(ctx, opt)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Write(ctx, func(q Executor) error {
		_, e := q.ExecContext(ctx, "CREATE TABLE marker(id INTEGER PRIMARY KEY)")
		return e
	}); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(filepath.Dir(opt.Path), "full.db")
	if _, err = OnlineBackup(ctx, opt.Path, backup); err != nil {
		t.Fatal(err)
	}
	if _, err = RestoreBackup(ctx, backup, opt.Path, true); err == nil {
		t.Fatal("restore bypassed active owner lock")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	// Uncheckpointed sidecars must be handled explicitly, silently removed.
	sidecar := opt.Path + "-wal"
	if err = os.WriteFile(sidecar, []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = RestoreBackup(ctx, backup, opt.Path, true); err == nil || !strings.Contains(err.Error(), "checkpoint") {
		t.Fatalf("unsafe sidecar accepted: %v", err)
	}
	if err = os.Remove(sidecar); err != nil {
		t.Fatal(err)
	}
	rollback, err := RestoreBackup(ctx, backup, opt.Path, true)
	if err != nil {
		t.Fatal(err)
	}
	if rollback == "" {
		t.Fatal("restore did not preserve previous DB")
	}
	if _, err = os.Stat(rollback); err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyBackup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(backup, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteAt([]byte("XXXX"), 0); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyBackup(ctx, backup); err == nil {
		t.Fatal("tampered snapshot verified")
	}
	if _, err = RestoreBackup(ctx, backup, opt.Path, true); err == nil {
		t.Fatal("tampered snapshot restored")
	}
}
