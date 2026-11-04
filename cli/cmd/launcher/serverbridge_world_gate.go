package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Этот барьер намеренно размещён в корне сервера, а не в настраиваемом хранилище резервных
// копий. Host Supervisor и резервное копирование — отдельные процессы CLI; они должны
// конкурировать за один атомарно создаваемый каталог до запуска новой JVM или копирования
// байтов остановленного мира. После сбоя владельца каталог остаётся: безопаснее отказать,
// чем угадывать, устарело ли владение. Файловые системы без атомарного создания каталога не
// поддерживаются.
type worldHostGate04110 struct {
	PID             int    `json:"pid"`
	ProcessIdentity string `json:"processIdentity"`
	Purpose         string `json:"purpose"`
	CreatedAt       string `json:"createdAt"`
}

func worldBackupHostGatePath04110(root string) string {
	return filepath.Join(hostPaths01910(root)["dir"], "world-maintenance.gate")
}

func worldBackupHostGateAcquire04110(root, purpose string) (func(), error) {
	if purpose != "backup" && purpose != "start" {
		return nil, errors.New("invalid host gate purpose")
	}
	identity := hostOwnIdentity0282()
	if identity == "" {
		return nil, errors.New("cannot prove gate owner OS process identity")
	}
	path := worldBackupHostGatePath04110(root)
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return nil, err
	}
	if err := worldBackupNoSymlinkAncestors02810(parent); err != nil {
		return nil, err
	}
	if err := os.Mkdir(path, 0700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("world maintenance gate occupied; JVM start and world backup blocked until owner releases or operator reconciles %s", path)
		}
		return nil, err
	}
	owner := worldHostGate04110{PID: os.Getpid(), ProcessIdentity: identity, Purpose: purpose, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	raw, err := json.Marshal(owner)
	if err == nil {
		err = os.WriteFile(filepath.Join(path, "owner.json"), raw, 0600)
	}
	if err == nil {
		err = worldBackupSyncDir02810(path)
	}
	if err == nil {
		err = worldBackupSyncDir02810(parent)
	}
	if err != nil {
		// Процесс создал барьер и владеет им; освобождайте только при этой синхронной
		// ошибке. Сбой в данном окне намеренно сохраняет блокировку.
		_ = os.Remove(filepath.Join(path, "owner.json"))
		_ = os.Remove(path)
		return nil, err
	}
	return func() {
		var current worldHostGate04110
		if worldBackupReadJSON02810(filepath.Join(path, "owner.json"), &current) != nil || current != owner {
			return
		}
		_ = os.Remove(filepath.Join(path, "owner.json"))
		_ = os.Remove(path)
		_ = worldBackupSyncDir02810(parent)
	}, nil
}

// Явное согласование устаревшего барьера. Не удаляйте автоматически незнакомый или
// частично записанный барьер после сбоя: при неопределённом снимке мира автоматический
// перезапуск JVM запрещён. Живой супервизор или JVM блокирует восстановление даже
// после исчезновения прежнего владельца.
func worldBackupHostGateRecover04110(root string) error {
	path := worldBackupHostGatePath04110(root)
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe host gate entry")
	}
	var owner worldHostGate04110
	if err = worldBackupReadJSON02810(filepath.Join(path, "owner.json"), &owner); err != nil {
		return fmt.Errorf("unverifiable gate owner: %w; manual investigation required", err)
	}
	if owner.PID <= 0 || owner.ProcessIdentity == "" || (owner.Purpose != "backup" && owner.Purpose != "start") {
		return errors.New("unverifiable gate identity")
	}
	if hostIdentityMatches0282(owner.PID, owner.ProcessIdentity) {
		return fmt.Errorf("host gate still owned by live process %d", owner.PID)
	}
	paths := hostPaths01910(root)
	state, stateErr := readServerBridgeHostRuntime01910(paths["runtime"])
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return fmt.Errorf("cannot reconcile JVM state: %w", stateErr)
	}
	if stateErr == nil {
		if hostIdentityMatches0282(state.ProcessPID, state.ProcessIdentity) ||
			hostIdentityMatches0282(state.SupervisorPID, state.SupervisorIdentity) ||
			(state.ProcessPID > 0 && state.ProcessIdentity == "" && updaterProcessAlive0156(state.ProcessPID)) ||
			(state.SupervisorPID > 0 && state.SupervisorIdentity == "" && updaterProcessAlive0156(state.SupervisorPID)) {
			return errors.New("JVM or supervisor still alive; refusing maintenance gate recovery")
		}
	}
	lock, lockErr := readServerBridgeHostLock01910(paths["lock"])
	if lockErr != nil && !errors.Is(lockErr, os.ErrNotExist) {
		return fmt.Errorf("cannot verify host lock: %w", lockErr)
	}
	if lockErr == nil && (hostIdentityMatches0282(lock.PID, lock.Identity) || (lock.Identity == "" && updaterProcessAlive0156(lock.PID))) {
		return errors.New("host supervisor lock remains active")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 1 || entries[0].Name() != "owner.json" || !entries[0].Type().IsRegular() {
		return errors.New("unexpected contents of maintenance gate")
	}
	if err := os.Remove(filepath.Join(path, "owner.json")); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return worldBackupSyncDir02810(filepath.Dir(path))
}
