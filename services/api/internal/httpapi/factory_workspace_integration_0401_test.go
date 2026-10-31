package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

func sampleFactory0401() (repository.BuildWorkspace, factoryPlanView02710, factoryBuilderJob02710) {
	ws := repository.BuildWorkspace{ID: "workspace", ProjectID: "p", OwnerID: "user", ProfileID: "profile", Channel: "stable", Version: "1", State: "importing"}
	ws.Settings.Minecraft = model.MinecraftInfo{Version: "1.21.1", Loader: "fabric", LoaderVersion: "0.16.13"}
	ws.Settings.Runtime.Java.MajorVersion = 21
	p := factoryPlanView02710{MinecraftVersion: "1.21.1", Loader: "fabric", LoaderVersion: "0.16.13"}
	p.Java.Major = 21
	p.Targets = append(p.Targets, struct {
		OS   string `json:"os"`
		Arch string `json:"arch"`
	}{"linux", "x86_64"})
	p.Launch.ProfilePath = "versions/fabric-loader-0.16.13-1.21.1/fabric-loader-0.16.13-1.21.1.json"
	p.Launch.MainClass = "net.fabricmc.loader.impl.launch.knot.KnotClient"
	p.Outputs = append(p.Outputs, struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	}{p.Launch.ProfilePath, strings.Repeat("a", 64), 42})
	return ws, p, factoryBuilderJob02710{Request: factoryBuilderRequest02710{Minecraft: "1.21.1", Loader: "fabric", LoaderVersion: "0.16.13", Target: "linux/x86_64"}}
}

func TestFactoryPrepareWorkspace0401(t *testing.T) {
	ws, p, job := sampleFactory0401()
	got, err := factoryPrepareWorkspace0401(ws, p, job, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if got.Settings.Runtime.Launch.ClasspathStrategy != "mojang" || got.Settings.Runtime.Launch.VersionMetadataPath != p.Launch.ProfilePath || len(got.Files) != 1 || got.Files[0].TargetOS[0] != "linux" || !got.Files[0].Selected {
		t.Fatalf("unexpected imported workspace: %+v", got)
	}
	if len(ws.Files) != 0 || ws.Settings.Runtime.Launch.ClasspathStrategy != "" {
		t.Fatal("mutated caller workspace")
	}
	cases := []struct {
		name   string
		change func(*repository.BuildWorkspace, *factoryPlanView02710, *factoryBuilderJob02710)
	}{
		{"java-mismatch", func(w *repository.BuildWorkspace, p *factoryPlanView02710, j *factoryBuilderJob02710) {
			w.Settings.Runtime.Java.MajorVersion = 17
		}},
		{"loader-mismatch", func(w *repository.BuildWorkspace, p *factoryPlanView02710, j *factoryBuilderJob02710) {
			p.LoaderVersion = "0.16.12"
		}},
		{"empty-metadata", func(w *repository.BuildWorkspace, p *factoryPlanView02710, j *factoryBuilderJob02710) {
			p.Launch.ProfilePath = ""
		}},
		{"path-traversal", func(w *repository.BuildWorkspace, p *factoryPlanView02710, j *factoryBuilderJob02710) {
			p.Outputs[0].Path = "../versions"
		}},
		{"missing-metadata", func(w *repository.BuildWorkspace, p *factoryPlanView02710, j *factoryBuilderJob02710) {
			p.Outputs[0].Path = "versions/other.json"
		}},
		{"large-file", func(w *repository.BuildWorkspace, p *factoryPlanView02710, j *factoryBuilderJob02710) {
			p.Outputs[0].Size = 1025
		}},
		{"occupied", func(w *repository.BuildWorkspace, p *factoryPlanView02710, j *factoryBuilderJob02710) {
			w.Files = []repository.BuildFile{{Path: "a"}}
		}},
		{"unsafe-override", func(w *repository.BuildWorkspace, p *factoryPlanView02710, j *factoryBuilderJob02710) {
			w.Settings.Runtime.Launch.ClasspathEntries = []string{"evil.jar"}
		}},
		{"wrong-target", func(w *repository.BuildWorkspace, p *factoryPlanView02710, j *factoryBuilderJob02710) {
			j.Request.Target = "other/amd64"
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w, pl, j := sampleFactory0401()
			c.change(&w, &pl, &j)
			if _, err := factoryPrepareWorkspace0401(w, pl, j, 1024); err == nil {
				t.Fatal("accepted invalid factory delivery")
			}
		})
	}
}

func TestFactoryReadSource0401(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "versions", "demo"), 0700); err != nil {
		t.Fatal(err)
	}
	path := "versions/demo/demo.json"
	data := []byte(`{"mainClass":"example.Client"}`)
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(path)), data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	f := struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	}{path, hex.EncodeToString(sum[:]), int64(len(data))}
	b, err := factoryReadSource0401(root, f, 1024)
	if err != nil || string(b) != string(data) {
		t.Fatalf("read verified output: %v", err)
	}
	f.SHA256 = strings.Repeat("0", 64)
	if _, err = factoryReadSource0401(root, f, 1024); err == nil {
		t.Fatal("accepted corrupted factory file")
	}
	f.SHA256 = hex.EncodeToString(sum[:])
	f.Path = "../demo.json"
	if _, err = factoryReadSource0401(root, f, 1024); err == nil {
		t.Fatal("accepted traversal")
	}
	f.Path = "versions/demo/demo.json"
	f.Size = 1025
	if _, err = factoryReadSource0401(root, f, 1024); err == nil {
		t.Fatal("accepted oversized file")
	}
	f.Size = int64(len(data))
	if err = os.Remove(filepath.Join(root, filepath.FromSlash(path))); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(root, "somewhere"), filepath.Join(root, filepath.FromSlash(path))); err == nil {
		if _, err = factoryReadSource0401(root, f, 1024); err == nil {
			t.Fatal("accepted symlink")
		}
	}
}
