package repository

import (
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"testing"
)

func TestMemoryReleaseSnapshotPinnedThroughAllMutations0222(t *testing.T) {
	r := NewMemoryRepository("https://launcher.example")
	release, err := r.CreateVersion("demo-project", "vanilla", "beta", "integrity-0222")
	if err != nil {
		t.Fatal(err)
	}
	frozen := *release.Manifest.ProfileSnapshot
	// Вызывающий не должен менять сохранённый релиз через указатель, возвращённый
	// CreateVersion.
	release.Manifest.ProfileSnapshot.Revision = 123
	current, _ := r.ListVersions("demo-project")
	var draft model.ReleaseVersion
	for _, v := range current {
		if v.ID == release.ID {
			draft = v
		}
	}
	if draft.Manifest.ProfileSnapshot == nil || *draft.Manifest.ProfileSnapshot != frozen {
		t.Fatal("CreateVersion раскрыл ссылку на изменяемый снимок")
	}
	// Законное изменение метаданных черновика сохраняет закреплённую ревизию.
	draft.Manifest.Minecraft.Version = "1.21.1"
	saved, err := r.UpdateVersionManifest(draft.ProjectID, draft.ID, draft.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if *saved.Manifest.ProfileSnapshot != frozen {
		t.Fatal("При корректном обновлении метаданных снимок потерял фиксацию")
	}
	newer := frozen
	newer.Revision++
	changed := saved.Manifest
	changed.ProfileSnapshot = &newer
	if _, err := r.UpdateVersionManifest(draft.ProjectID, draft.ID, changed); err == nil {
		t.Fatal("Ошибочно принято внедрение ревизии снимка")
	}
	if _, err := r.PublishVersionWithManifest(draft.ProjectID, draft.ProfileID, draft.Channel, draft.Version, changed); err == nil {
		t.Fatal("При публикации подставлен другой снимок")
	}
	// Постороннее изменение профиля не влияет на зафиксированный черновик.
	profiles, _ := r.ListProfiles("demo-project")
	for _, p := range profiles {
		if p.ID == "vanilla" {
			p.Name = "Renamed"
			if _, err := r.SaveProfile(p); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	saved, err = r.PublishVersionWithManifest(draft.ProjectID, draft.ProfileID, draft.Channel, draft.Version, saved.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if *saved.Manifest.ProfileSnapshot != frozen {
		t.Fatal("Опубликованный снимок изменился")
	}
	published, err := r.GetManifest("demo-project", "vanilla", "beta")
	if err != nil {
		t.Fatal(err)
	}
	published.ProfileSnapshot.Spec.Name = "injected"
	current, _ = r.ListVersions("demo-project")
	for _, v := range current {
		if v.ID == release.ID {
			if *v.Manifest.ProfileSnapshot != frozen {
				t.Fatal("Публичное чтение изменило сохранённый манифест")
			}
			v.Manifest.ProfileSnapshot.Revision = 10
		}
	}
	again, err := r.GetManifest("demo-project", "vanilla", "beta")
	if err != nil || *again.ProfileSnapshot != frozen {
		t.Fatal("ListVersions раскрыл ссылку на изменяемый снимок")
	}
}
