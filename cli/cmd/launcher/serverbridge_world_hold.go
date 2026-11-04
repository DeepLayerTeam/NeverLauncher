package main

// 0.51.8: удерживайте СУЩЕСТВУЮЩИЙ барьер запуска Host Supervisor на протяжении всей
// согласованной группы PostgreSQL/S3/миров. Барьер захватывается при создании копии мира и
// атомарно переводится в длительное удержание до возможного освобождения первоначальным
// процессом. Это исключает промежуток между копированием мира и заморозкой БД. Сбой оператора
// или SSH оставляет барьер (отказ при неопределённости).

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var worldCohortID0518 = regexp.MustCompile(`^[0-9a-f]{32}$`)

const worldCohortHoldFile0518 = "cohort-hold-0518"

func worldBackupPersistCohortHold0518(root, holdID, backupID string) error {
	if !worldCohortID0518.MatchString(holdID) || !worldBackupID02810.MatchString(backupID) {
		return errors.New("cohort hold needs valid operation and backup IDs")
	}
	gate := worldBackupHostGatePath04110(root)
	var owner worldHostGate04110
	if err := worldBackupReadJSON02810(filepath.Join(gate, "owner.json"), &owner); err != nil {
		return fmt.Errorf("unverifiable cohort gate owner: %w", err)
	}
	if owner.Purpose != "backup" || owner.PID != os.Getpid() || owner.ProcessIdentity != hostOwnIdentity0282() {
		return errors.New("cohort hold must be installed by current world-backup gate owner")
	}
	path := filepath.Join(gate, worldCohortHoldFile0518)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	count, err := file.WriteString(holdID + "\n" + backupID + "\n")
	if err == nil && count != 66 {
		err = io.ErrShortWrite
	}
	if syncErr := file.Sync(); err == nil {
		err = syncErr
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = worldBackupSyncDir02810(gate)
	}
	if err != nil {
		// Никогда не удаляйте барьер, если длительное удержание могло сохраниться на диске;
		// прерванное развёртывание требует отдельного расследования.
		return fmt.Errorf("cohort hold may be partially committed; gate must remain fenced: %w", err)
	}
	return nil
}

func worldBackupReleaseCohortHold0518(root, holdID string) error {
	if !worldCohortID0518.MatchString(holdID) {
		return errors.New("release requires a 32-character hexadecimal --hold-id")
	}
	gate := worldBackupHostGatePath04110(root)
	info, err := os.Lstat(gate)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("unsafe cohort gate directory")
	}
	var owner worldHostGate04110
	if err = worldBackupReadJSON02810(filepath.Join(gate, "owner.json"), &owner); err != nil {
		return fmt.Errorf("unverifiable gate owner: %w", err)
	}
	if owner.Purpose != "backup" || owner.PID <= 0 || owner.ProcessIdentity == "" {
		return errors.New("cohort gate does not belong to a trusted backup")
	}
	holdPath := filepath.Join(gate, worldCohortHoldFile0518)
	fd, err := os.Open(holdPath)
	if err != nil {
		return err
	}
	holdInfo, err := fd.Stat()
	if err != nil {
		fd.Close()
		return err
	}
	linkInfo, err := os.Lstat(holdPath)
	if err != nil {
		fd.Close()
		return err
	}
	if !holdInfo.Mode().IsRegular() || !os.SameFile(holdInfo, linkInfo) ||
		holdInfo.Mode().Perm()&0077 != 0 || holdInfo.Size() != 66 {
		fd.Close()
		return errors.New("unsafe cohort hold token")
	}
	buf := make([]byte, 66)
	n, err := io.ReadFull(fd, buf)
	fd.Close()
	if err != nil || n != len(buf) {
		return errors.New("corrupt cohort hold token")
	}
	text := string(buf)
	if !strings.HasPrefix(text, holdID+"\n") || !worldBackupID02810.MatchString(strings.TrimSpace(text[33:])) {
		return errors.New("cohort operation ID mismatch; refusing release")
	}
	entries, err := os.ReadDir(gate)
	if err != nil {
		return err
	}
	if len(entries) != 2 || entries[0].Name() != worldCohortHoldFile0518 || entries[1].Name() != "owner.json" {
		return errors.New("cohort gate contains unexpected entries")
	}
	// Нельзя освобождать барьер, пока управляемая JVM работает или запускается.
	if err = worldBackupQuiesce02810(root, "stopped"); err != nil {
		return err
	}
	if err = os.Remove(holdPath); err != nil {
		return err
	}
	if err = os.Remove(filepath.Join(gate, "owner.json")); err != nil {
		return err
	}
	if err = os.Remove(gate); err != nil {
		return err
	}
	return worldBackupSyncDir02810(filepath.Dir(gate))
}
