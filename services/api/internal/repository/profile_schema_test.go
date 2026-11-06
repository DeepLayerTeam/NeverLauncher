package repository

import (
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"testing"
)

func TestProfileVersionAndReleaseSnapshot0221(t *testing.T) {
	r := NewMemoryRepository("http://localhost")
	profiles, err := r.ListProfiles("demo-project")
	if err != nil {
		t.Fatal(err)
	}
	var p model.Profile
	for _, item := range profiles {
		if item.ID == "vanilla" {
			p = item
		}
	}
	if p.Revision != 1 {
		t.Fatalf("Неожиданная устаревшая ревизия: %+v", p)
	}
	release, err := r.CreateVersion("demo-project", "vanilla", "beta", "profile-0221")
	if err != nil {
		t.Fatal(err)
	}
	if release.Manifest.SchemaVersion != "2.0" || release.Manifest.ProfileSnapshot == nil {
		t.Fatal("В черновике отсутствует неизменяемый снимок v2")
	}
	old := *release.Manifest.ProfileSnapshot
	p.Name = "Renamed"
	saved, err := r.SaveProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision != 2 || saved.Digest == old.Digest {
		t.Fatal("Изменение профиля не создало ревизию")
	}
	history, err := r.ListProfileRevisions("demo-project", "vanilla")
	if err != nil || len(history) != 2 {
		t.Fatalf("История %v: %v", history, err)
	}
	if history[0].Digest != old.Digest {
		t.Fatal("Старая история переписана")
	}
	versions, _ := r.ListVersions("demo-project")
	for _, v := range versions {
		if v.ID == release.ID && v.Manifest.ProfileSnapshot.Digest != old.Digest {
			t.Fatal("Снимок релиза неожиданно изменился")
		}
	}
	p.Revision = 1
	p.Name = "stale update"
	if _, err := r.SaveProfile(p); err != ErrConflict {
		t.Fatalf("Ожидался конфликт CAS, получено %v", err)
	}
	saved.Name = "Renamed"
	same, err := r.SaveProfile(saved)
	if err != nil || same.Revision != 2 {
		t.Fatal("Пустая операция изменила ревизию")
	}
	if _, err := r.GetManifest("demo-project", "vanilla", "beta"); err != ErrNotFound {
		t.Fatalf("Черновик попал в публичный манифест: %v", err)
	}
}
