package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

type rehearsalFixture struct{ Action, UUID, Evidence string }

func rehearsalFixtureClientPath() string {
	if runtime.GOOS == "windows" {
		return "bin/client.exe"
	}
	return "bin/client"
}

// The copied test binary acts as a native fixture only when launched through
// an explicitly created sidecar. The real runner still starts a process and
// verifies RCON before/after; fixtures cannot assert production certification.
func init() {
	path, err := os.Executable()
	if err != nil {
		return
	}
	raw, err := os.ReadFile(path + ".fixture.json")
	if err != nil {
		return
	}
	var fixture rehearsalFixture
	if json.Unmarshal(raw, &fixture) != nil {
		os.Exit(2)
	}
	marker := filepath.Join(os.Getenv("HOME"), "client-started")
	switch fixture.Action {
	case "client":
		if os.WriteFile(marker, []byte("started"), 0600) != nil {
			os.Exit(2)
		}
		time.Sleep(60 * time.Second)
	case "probe", "disconnect":
		if fixture.Action == "disconnect" {
			_ = os.Remove(marker)
		}
		if json.NewEncoder(os.Stdout).Encode(map[string]any{"passed": true, "uuid": fixture.UUID, "evidenceFile": fixture.Evidence}) != nil {
			os.Exit(2)
		}
	case "exit":
	case "fail":
		os.Exit(1)
	default:
		os.Exit(2)
	}
	os.Exit(0)
}

func writeRehearsalFixture(t *testing.T, root, rel string, fixture rehearsalFixture) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		source, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		// Hardlink avoids copying a large Go test executable for every probe.
		if err = os.Link(source, path); err != nil {
			in, err := os.Open(source)
			if err != nil {
				t.Fatal(err)
			}
			defer in.Close()
			out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
			if err != nil {
				t.Fatal(err)
			}
			_, copyErr := io.Copy(out, in)
			closeErr := out.Close()
			if copyErr != nil {
				t.Fatal(copyErr)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
		}
	} else if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path+".fixture.json", raw, 0600); err != nil {
		t.Fatal(err)
	}
}
