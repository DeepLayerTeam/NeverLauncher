package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRehearsalExecAndSubmission03310(t *testing.T) {
	dir := t.TempDir()
	run := "1234567890abcdef"
	stage := "stage_abcdefgh12345678"
	h := strings.Repeat("a", 64)
	must := func(rel string, b []byte, mode os.FileMode) {
		t.Helper()
		p := filepath.Join(dir, rel)
		if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(p, b, mode); e != nil {
			t.Fatal(e)
		}
	}
	marker, _ := json.Marshal(map[string]any{"format": "never/migration-stage/v1", "runId": run, "stageId": stage, "isolated": true})
	must(".migration-stage.json", marker, 0600)
	player := rehearsalPlayer03310{SourceID: "fileauth:42", UUID: "12345678-1234-1234-1234-123456789abc", InventorySHA256: h, PermissionsSHA256: h, Economy: "100.00", SkinSHA256: h, Admin: true}
	snapshot := rehearsalSnapshot03310{WorldSHA256: h, Loader: "forge", OptionalPresetSHA256: h, Players: []rehearsalPlayer03310{player}}
	data, _ := json.Marshal(snapshot)
	must("source-snapshot.json", data, 0600)
	must("target-snapshot.json", data, 0600)
	address, closeRCON := setupRehearsalRCON0447(t, dir, player.UUID)
	defer closeRCON()
	must("rcon-password", []byte("test-pass\n"), 0600)
	must("bin/client", []byte("#!/bin/sh\ntouch \"$HOME/client-started\"\nexec sleep 60\n"), 0700)
	liveConfig, _ := json.Marshal(rehearsalLiveConfig0447{ClientPath: "bin/client", PlayerName: "Steve", PlayerUUID: player.UUID, RCONAddress: address, RCONPasswordFile: "rcon-password", TimeoutSeconds: 10})
	must("live-session.json", liveConfig, 0600)
	for _, name := range rehearsalRequired03310 {
		must("evidence/"+name, []byte("real-test-evidence"), 0600)
		script := "#!/bin/sh\nprintf '{\"passed\":true,\"uuid\":\"" + player.UUID + "\",\"evidenceFile\":\"evidence/" + name + "\"}'\n"
		must("probes/"+name, []byte(script), 0700)
	}
	report, e := migrationRehearsalRun03310(context.Background(), dir, run, h)
	if e != nil || len(report.Probes) != 7 || report.LiveSession == nil || report.Ready || report.CutoverAllowed || report.Probes[0].EvidenceSHA256 == "" {
		t.Fatalf("runner: %+v %v", report, e)
	}
	sent := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent = true
		if r.Header.Get("X-Migration-Rehearsal-Confirm") != run || r.URL.Path != "/api/v1/admin/migration-runs/"+run+"/rehearsal" {
			t.Error("маршрут или подтверждение не совпадают")
		}
		var x rehearsalReport03310
		if e := json.NewDecoder(r.Body).Decode(&x); e != nil || len(x.Probes) != 7 || x.LiveSession == nil || x.Ready || x.CutoverAllowed {
			t.Errorf("Некорректная полезная нагрузка: %v %+v", e, x)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"ready":false,"cutoverAllowed":false}}`))
	}))
	defer server.Close()
	_ = os.Remove(filepath.Join(dir, "client-started"))
	if e = handleMigrationRehearsal03310([]string{"--backend", server.URL, "--token", "test", "--run", run, "--stage", dir, "--inventory-sha256", h, "--output", filepath.Join(dir, "report.json")}); e != nil {
		t.Fatal(e)
	}
	if !sent {
		t.Fatal("отчёт не был отправлен")
	}
	_ = os.Remove(filepath.Join(dir, "client-started"))
	must("probes/join", []byte("#!/bin/sh\nexit 1\n"), 0700)
	if _, e = migrationRehearsalRun03310(context.Background(), dir, run, h); e == nil {
		t.Fatal("допущена неудачная команда реального подключения")
	}
	_ = os.Remove(filepath.Join(dir, "client-started"))
	must("probes/join", []byte("#!/bin/sh\nprintf '{\"passed\":true,\"uuid\":\""+player.UUID+"\",\"evidenceFile\":\"evidence/join\"}'\n"), 0700)
	must("probes/skins", []byte("#!/bin/sh\nrm -f \"$HOME/client-started\"\nprintf '{\"passed\":true,\"uuid\":\""+player.UUID+"\",\"evidenceFile\":\"evidence/skins\"}'\n"), 0700)
	if _, e = migrationRehearsalRun03310(context.Background(), dir, run, h); e == nil {
		t.Fatal("допущено отключение игрока до проверки")
	}
}
func TestRehearsalPathTraversal03310(t *testing.T) {
	dir := t.TempDir()
	if _, e := rehearsalPath03310(dir, "../outside"); e == nil {
		t.Fatal("допущен выход за пределы пути")
	}
	outside := t.TempDir()
	if e := os.Symlink(outside, filepath.Join(dir, "escape")); e != nil {
		t.Fatal(e)
	}
	if _, e := rehearsalPath03310(dir, "escape"); e == nil {
		t.Fatal("Разрешён выход за пределы каталога через символьную ссылку")
	}
}

// Минимальный тестовый сервер RCON на уровне протокола; ложное passed=true не
// позволяет обойти реальные проверки сети и процесса. В производстве действующий
// Java-сервер обслуживает /list uuids по тому же протоколу.
func setupRehearsalRCON0447(t *testing.T, stage, uuid string) (string, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				id, kind, pass, e := rehearsalRCONRead0447(c)
				if e != nil {
					return
				}
				if id != 71 || kind != 3 || pass != "test-pass" {
					_ = rehearsalRCONPacket0447(c, -1, 2, "")
					return
				}
				_ = rehearsalRCONPacket0447(c, 71, 2, "")
				id, kind, command, e := rehearsalRCONRead0447(c)
				if e != nil || kind != 2 || command != "list uuids" {
					return
				}
				text := "There are 0 of a max of 20 players online:"
				if _, e := os.Stat(filepath.Join(stage, "client-started")); e == nil {
					text = fmt.Sprintf("There are 1 of a max of 20 players online: Steve (%s)", uuid)
				}
				_ = rehearsalRCONPacket0447(c, id, 0, text)
			}()
		}
	}()
	return l.Addr().String(), func() { _ = l.Close(); <-done }
}

func TestRehearsalLiveNoSyntheticSession0447(t *testing.T) {
	dir := t.TempDir()
	uuid := "12345678-1234-1234-1234-123456789abc"
	address, shutdown := setupRehearsalRCON0447(t, dir, uuid)
	defer shutdown()
	write := func(path, text string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, path)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, path), []byte(text), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("rcon-password", "test-pass", 0600)
	write("bin/client", "#!/bin/sh\nexit 0\n", 0700)
	cfg, _ := json.Marshal(rehearsalLiveConfig0447{ClientPath: "bin/client", PlayerName: "Steve", PlayerUUID: uuid, RCONAddress: address, RCONPasswordFile: "rcon-password", TimeoutSeconds: 10})
	write("live-session.json", string(cfg), 0600)
	src := rehearsalSnapshot03310{Players: []rehearsalPlayer03310{{UUID: uuid}}}
	if _, _, _, err := rehearsalLaunchLive0447(context.Background(), dir, src); err == nil {
		t.Fatal("успешной признана работа клиента без реального подключения")
	}
	write("bin/client", "#!/bin/sh\ntouch \"$HOME/client-started\"\nexec sleep 30\n", 0700)
	write("client-started", "", 0600)
	if _, _, _, err := rehearsalLaunchLive0447(context.Background(), dir, src); err == nil {
		t.Fatal("допущен игрок, подключённый ещё до запуска")
	}
	cfgBytes, _ := json.Marshal(rehearsalLiveConfig0447{ClientPath: "bin/client", PlayerName: "Steve", PlayerUUID: uuid, RCONAddress: "example.com:25575", RCONPasswordFile: "rcon-password", TimeoutSeconds: 10})
	write("live-session.json", string(cfgBytes), 0600)
	if _, _, _, err := rehearsalLaunchLive0447(context.Background(), dir, src); err == nil {
		t.Fatal("Удалённый доступ через RCON ошибочно разрешён")
	}
	if rehearsalRCONHasPlayer0447("Eve ("+uuid+")", "Steve", uuid) {
		t.Fatal("UUID другого игрока ошибочно принят")
	}
}
