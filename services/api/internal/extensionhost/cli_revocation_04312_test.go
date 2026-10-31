package extensionhost

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/extensionlifecycle"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
)

// The actual Go test executable is the native CLI fixture. Running the same
// test executable avoids Python/shebang skips on Windows and exercises the
// host protocol and real process termination on every target OS/architecture.
func TestNativeCLIHelper04312(t *testing.T) {
	if os.Getenv("LAUNCHER_EXTENSION_TARGET") != "cli" || os.Getenv("LAUNCHER_EXTENSION_INSTANCE_ID") == "" {
		return
	}
	body, err := json.Marshal(map[string]any{
		"protocolVersion": ProtocolVersion,
		"extensionId":     os.Getenv("LAUNCHER_EXTENSION_ID"),
		"instanceId":      os.Getenv("LAUNCHER_EXTENSION_INSTANCE_ID"),
		"pid":             os.Getpid(),
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, os.Getenv("LAUNCHER_EXTENSION_HOST_URL")+"/v1/hello", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+os.Getenv("LAUNCHER_EXTENSION_HOST_TOKEN"))
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("native CLI hello denied: %d", response.StatusCode)
	}
	time.Sleep(30 * time.Second)
}

func TestNativeCLIRevocationStopsRunningProcess04312(t *testing.T) {
	for _, revocation := range []string{"grant", "emergency", "install"} {
		t.Run(revocation, func(t *testing.T) {
			root := t.TempDir()
			repo := repository.NewMemoryRepository("http://localhost")
			id := "example.cli-revoke"
			extension := ""
			if runtime.GOOS == "windows" {
				extension = ".exe"
			}
			manifest := model.ExtensionManifest{
				SchemaVersion: "2.0", ID: id, Name: "Native CLI", Version: "1.0.0", Publisher: "example", API: "3.7",
				Targets: []model.ExtensionTarget{{Kind: "cli", Entrypoint: "cli/tool" + extension}}, Permissions: []string{"cli:contribute"},
				CLI: &model.ExtensionCLIContributions{Namespace: "ops", Commands: []model.ExtensionCLICommand{{Name: "wait"}}},
			}
			ctx := context.Background()
			if _, err := repo.SaveExtensionVersion(ctx, manifest); err != nil {
				t.Fatal(err)
			}
			install, err := repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{
				ExtensionID: id, Scope: "global", DesiredVersion: "1.0.0", CurrentVersion: "1.0.0",
				DesiredState: model.ExtensionInstallStateEnabled, CurrentState: model.ExtensionInstallStateEnabled,
				Enabled: true, Operation: "install", ExpectedGeneration: 0,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := repo.GrantExtensionPermission(ctx, model.ExtensionPermissionGrant{
				ExtensionID: id, Scope: "global", Permission: "cli:contribute", GrantedBy: "test",
			}); err != nil {
				t.Fatal(err)
			}
			payload, err := extensionlifecycle.CurrentPayloadDir(root, "global", "", id)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(payload, "cli"), 0755); err != nil {
				t.Fatal(err)
			}
			// Copy the signed-by-CI test executable instead of relying on an
			// externally installed interpreter or architecture emulation.
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			binary := filepath.Join(payload, "cli", "tool"+extension)
			src, err := os.Open(executable)
			if err != nil {
				t.Fatal(err)
			}
			dst, err := os.OpenFile(binary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
			if err != nil {
				_ = src.Close()
				t.Fatal(err)
			}
			_, copyErr := io.Copy(dst, src)
			closeErr := dst.Close()
			_ = src.Close()
			if copyErr != nil {
				t.Fatal(copyErr)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}

			host := New(Config{ExtensionRoot: root, StartupTimeout: 8 * time.Second, StopTimeout: 2 * time.Second}, repo, storage.NewLocalStorage(t.TempDir()))
			if err := host.Start(ctx); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				done, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				_ = host.Close(done)
			})
			finished := make(chan error, 1)
			go func() {
				_, err := host.RunCLI0209(ctx, install, []string{"-test.run=^TestNativeCLIHelper04312$"})
				finished <- err
			}()
			deadline := time.Now().Add(12 * time.Second)
			var state *processState
			for time.Now().Before(deadline) {
				host.mu.RLock()
				for _, st := range host.transients[Key{id, "global", ""}.String()] {
					state = st
					break
				}
				host.mu.RUnlock()
				if state != nil {
					state.mu.Lock()
					ready := !state.helloAt.IsZero() && state.state == "running"
					state.mu.Unlock()
					if ready {
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
			}
			if state == nil {
				t.Fatal("native CLI never registered")
			}
			state.mu.Lock()
			ready := !state.helloAt.IsZero()
			state.mu.Unlock()
			if !ready {
				t.Fatal("native CLI did not complete authenticated hello")
			}
			switch revocation {
			case "grant":
				if err := repo.RevokeExtensionPermission(ctx, id, "global", "", "cli:contribute"); err != nil {
					t.Fatal(err)
				}
			case "emergency":
				if _, err := repo.SetExtensionEmergencyDisable(ctx, model.ExtensionEmergencyDisable{ExtensionID: id, Scope: "global", Reason: "incident", Source: "test"}); err != nil {
					t.Fatal(err)
				}
			case "install":
				if _, err := repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{
					ExtensionID: id, Scope: "global", DesiredVersion: "1.0.0", CurrentVersion: "1.0.0",
					DesiredState: model.ExtensionInstallStateDisabled, CurrentState: model.ExtensionInstallStateDisabled,
					Enabled: false, Operation: "disable", ExpectedGeneration: install.Generation,
				}); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-finished:
				if err == nil {
					t.Fatal("CLI reported success despite revoked authority")
				}
			case <-time.After(8 * time.Second):
				t.Fatal("running native CLI survived trust revocation")
			}
		})
	}
}

func TestCLIAuthorityPreflightRejectsRevocation04312(t *testing.T) {
	host, repo, st := liveTrustFixture04210(t)
	ctx := context.Background()
	if _, err := repo.GrantExtensionPermission(ctx, model.ExtensionPermissionGrant{ExtensionID: st.key.ExtensionID, Scope: "global", Permission: "cli:contribute", GrantedBy: "test"}); err != nil {
		t.Fatal(err)
	}
	// Change the version's requested policy to include cli:contribute.
	st.install.CurrentVersion = "1.0.0"
	st.manifest.Permissions = append(st.manifest.Permissions, "cli:contribute")
	// The immutable repository manifest still lacks CLI permission: extra
	// grants alone must never authorize code execution.
	if err := host.enforceCLITrust04312(ctx, st); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("unrequested CLI privilege was granted: %v", err)
	}
	if _, err := repo.SetExtensionEmergencyDisable(ctx, model.ExtensionEmergencyDisable{ExtensionID: st.key.ExtensionID, Scope: "global", Reason: "incident", Source: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := host.enforceCLITrust04312(ctx, st); err == nil || !strings.Contains(err.Error(), "emergency-disabled") {
		t.Fatalf("emergency-disabled install passed CLI preflight: %v", err)
	}
}
