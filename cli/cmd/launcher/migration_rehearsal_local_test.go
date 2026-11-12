package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRehearseLocal04910LiveJoinAndFailClosed(t *testing.T) {
	root := t.TempDir()
	run := "run_04910_live_test"
	inventory := strings.Repeat("f", 64)
	uuid := "12345678-1234-1234-1234-123456789abc"
	put := func(rel string, value []byte, mode os.FileMode) {
		t.Helper()
		file := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, value, mode); err != nil {
			t.Fatal(err)
		}
	}
	stage := map[string]any{"format": "launcher/migration-stage/v1", "runId": run, "stageId": "isolated_run_04910_abcdefgh", "isolated": true}
	raw, _ := json.Marshal(stage)
	put(".migration-stage.json", raw, 0600)
	player := rehearsalPlayer03310{SourceID: "fileauth:42", UUID: uuid, InventorySHA256: inventory, PermissionsSHA256: inventory, Economy: "100.00", SkinSHA256: inventory}
	snapshot := rehearsalSnapshot03310{WorldSHA256: inventory, Loader: "forge", OptionalPresetSHA256: inventory, Players: []rehearsalPlayer03310{player}}
	raw, _ = json.Marshal(snapshot)
	put("source-snapshot.json", raw, 0600)
	put("target-snapshot.json", raw, 0600)
	addr, stop := setupRehearsalRCON0447(t, root, uuid)
	defer stop()
	put("rcon-password", []byte("test-pass\n"), 0600)
	put("bin/client", []byte("#!/bin/sh\ntouch \"$HOME/client-started\"\nexec sleep 60\n"), 0700)
	config, _ := json.Marshal(rehearsalLiveConfig0447{ClientPath: "bin/client", PlayerName: "Steve", PlayerUUID: uuid, RCONAddress: addr, RCONPasswordFile: "rcon-password", TimeoutSeconds: 10})
	put("live-session.json", config, 0600)
	for _, name := range rehearsalRequired03310 {
		put("evidence/"+name, []byte("staging-observation-"+name), 0600)
		put("probes/"+name, []byte("#!/bin/sh\nprintf '{\"passed\":true,\"uuid\":\""+uuid+"\",\"evidenceFile\":\"evidence/"+name+"\"}'\n"), 0700)
	}
	out := filepath.Join(root, "after-update.json")
	args := []string{"--run", run, "--stage", root, "--inventory-sha256", inventory, "--output", out}
	if err := handleMigrationRehearsalLocal04910(args); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var report rehearsalReport03310
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Ready || report.CutoverAllowed || report.LiveSession == nil || len(report.Probes) != 7 {
		t.Fatal("Только локальное свидетельство не должно подтверждать общую готовность или переключение")
	}
	if st, err := os.Stat(out); err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("Закрытые свидетельства: %v %v", st, err)
	}
	if err := handleMigrationRehearsalLocal04910(args); err == nil {
		t.Fatal("Перезапись ранее завершённого реального свидетельства должна быть отклонена")
	}
	if err := handleMigrationRehearsalLocal04910([]string{"--run", run, "--stage", root, "--inventory-sha256", inventory}); err == nil {
		t.Fatal("Отчёт нельзя выводить в стандартный поток вывода")
	}
	// Успешная нативная сессия не должна отменять отрицательные результаты независимых проверок.
	put("probes/join", []byte("#!/bin/sh\nexit 1\n"), 0700)
	args[len(args)-1] = filepath.Join(root, "failed.json")
	if err := handleMigrationRehearsalLocal04910(args); err == nil {
		t.Fatal("Неуспешная проверка ошибочно принята")
	}
	if _, err := os.Stat(args[len(args)-1]); !os.IsNotExist(err) {
		t.Fatal("Неуспешный запуск записал свидетельство об успехе")
	}
}
