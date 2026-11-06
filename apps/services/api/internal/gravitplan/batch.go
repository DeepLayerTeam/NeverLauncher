package gravitplan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	gc "gitflic.ru/skif4er/launcher/services/api/internal/gravitcontent"
	gd "gitflic.ru/skif4er/launcher/services/api/internal/gravitdetector"
	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
	gm "gitflic.ru/skif4er/launcher/services/api/internal/gravitmodules"
)

// Batch рассчитывается из одного неизменяемого проверенного по байтам ZIP Gravit и
// живого целевого снимка. Здесь не выполняются изменения, выдача прав или
// исполнение чужих JAR. Это не авторизация переключения.
const BatchFormat0492 = "launcher.gravit-multi-profile-dry-run.v1"
const MaxProfiles0492 = 32

type Dependency0492 struct {
	Component string `json:"component"`
	Requires  string `json:"requires"`
	Kind      string `json:"kind"` // dependency or conflict
}
type ProfileResult0492 struct {
	Destination     Destination      `json:"destination"`
	SourceDirectory string           `json:"sourceDirectory,omitempty"`
	Status          string           `json:"status"` // заблокировано или вручную, но никогда не «одобрено»
	PlanSHA256      string           `json:"planSha256,omitempty"`
	FilesSHA256     string           `json:"filesSha256,omitempty"`
	FileCount       int              `json:"fileCount"`
	TransferBytes   int64            `json:"transferBytes"`
	Dependencies    []Dependency0492 `json:"dependencies"`
	Blockers        []string         `json:"blockers"`
}
type Batch0492 struct {
	Format          string              `json:"format"`
	RunID           string              `json:"runId"`
	ProjectID       string              `json:"projectId"`
	SourceSHA256    string              `json:"sourceSha256"`
	InventorySHA256 string              `json:"inventorySha256"`
	TargetSHA256    string              `json:"targetSha256"`
	Profiles        []ProfileResult0492 `json:"profiles"`
	ProfileCount    int                 `json:"profileCount"`
	Status          string              `json:"status"` // заблокировано или вручную, но никогда не одобрено
	Blockers        []string            `json:"blockers"`
	BatchSHA256     string              `json:"batchSha256"`
}

func BatchDigest0492(b Batch0492) (string, error) {
	b.BatchSHA256 = ""
	encoded, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
func VerifyBatch0492(b Batch0492) error {
	if b.Format != BatchFormat0492 || len(b.BatchSHA256) != 64 || len(b.SourceSHA256) != 64 || len(b.TargetSHA256) != 64 || b.ProfileCount != len(b.Profiles) || b.ProfileCount < 1 || b.ProfileCount > MaxProfiles0492 {
		return errors.New("Некорректное значение: пробная миграция нескольких профилей")
	}
	digest, err := BatchDigest0492(b)
	if err != nil {
		return err
	}
	if digest != b.BatchSHA256 {
		return errors.New("Обнаружено изменение: пробная миграция нескольких профилей")
	}
	return nil
}

// BuildBatch0492 требует один раз закрепить и проверить архив через Inspect и затем
// передать неизменяемый spool. Для каждого профиля применяются тот же реальный
// конвертер содержимого и сборщик плана, что при одиночном импорте; недопустимый
// источник или неразрешённая зависимость не получают синтетический успех.
func BuildBatch0492(ctx context.Context, source io.ReaderAt, size int64, run, project, target string, existing map[string]bool, inventory inv.Inventory, compatibility gd.Report, modules gm.Report, identities IdentityPreview, destinations []Destination) (Batch0492, error) {
	out := Batch0492{Format: BatchFormat0492, RunID: run, ProjectID: project, SourceSHA256: inventory.SourceSHA256, InventorySHA256: inventory.ManifestSHA256, TargetSHA256: target, Profiles: []ProfileResult0492{}, Blockers: []string{}, Status: "manual"}
	if len(destinations) == 0 || len(destinations) > MaxProfiles0492 || run == "" || project == "" || len(target) != 64 || size != inventory.SourceBytes || compatibility.SourceSHA256 != inventory.SourceSHA256 || modules.SourceSHA256 != inventory.SourceSHA256 || modules.InventorySHA256 != inventory.ManifestSHA256 {
		return out, errors.New("Некорректное значение: «источник пакета, число целей или целевой снимок»")
	}
	if _, err := inventory.Manifest(); err != nil {
		return out, err
	}
	available := make(map[string]bool)
	for _, f := range inventory.Files {
		if f.Kind == "client_profile" {
			available[f.Path] = true
		}
	}
	if len(available) == 0 || len(available) != len(destinations) {
		return out, fmt.Errorf("every Gravit profile: требуется «однозначное сопоставление: в источнике %d, в запросе» %d", len(available), len(destinations))
	}
	mapped, ids := make(map[string]bool), make(map[string]bool)
	for _, d := range destinations {
		if !available[d.ProfilePath] || mapped[d.ProfilePath] || d.ProfileID == "" || d.ProfileName == "" || d.Loader == "" || (d.Loader != "vanilla" && d.LoaderVersion == "") || d.Channel == "" || d.Version == "" || len(d.ProfileID) > 128 || len(d.ProfileName) > 120 || len(d.Channel) > 128 || len(d.Version) > 128 || len(d.Loader) > 24 || len(d.LoaderVersion) > 128 {
			return out, errors.New("Исходный профиль недопустим, дублируется или не сопоставлен")
		}
		id := strings.ToLower(d.ProfileID)
		if ids[id] {
			return out, errors.New("Обнаружен дубликат: «идентификатор целевого профиля»")
		}
		ids[id], mapped[d.ProfilePath] = true, true
	}
	sort.Slice(destinations, func(i, j int) bool { return destinations[i].ProfilePath < destinations[j].ProfilePath })
	dirs := make(map[string]string)
	for _, d := range destinations {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		row := ProfileResult0492{Destination: d, Status: "blocked", Blockers: []string{}, Dependencies: []Dependency0492{}}
		content, err := gc.PreparePinned(ctx, source, size, inventory, d.ProfilePath, project, d.ProfileID, d.ProfileName, d.Loader, d.LoaderVersion)
		if err != nil {
			row.Blockers = append(row.Blockers, "Преобразование завершилось ошибкой: "+err.Error())
		} else {
			row.SourceDirectory, row.FilesSHA256, row.FileCount = content.SourceDirectory, content.FilesSHA256, len(content.Files)
			folded := strings.ToLower(content.SourceDirectory)
			// Совпадают полные или вложенные корни: a и a/modpack имеют общие файлы.
			// Помечайте каждый затронутый профиль, не только последний.
			for priorDir, prior := range dirs {
				if folded == priorDir || strings.HasPrefix(folded, priorDir+"/") || strings.HasPrefix(priorDir, folded+"/") {
					row.Blockers = append(row.Blockers, "Каталог клиента пересекается с "+prior)
					for i := range out.Profiles {
						if out.Profiles[i].Destination.ProfilePath == prior {
							out.Profiles[i].Blockers = append(out.Profiles[i].Blockers, "Каталог клиента пересекается с "+d.ProfilePath)
							out.Profiles[i].Status = "blocked"
						}
					}
				}
			}
			dirs[folded] = d.ProfilePath
			// Зависимости classpath разрешает тот же промышленный конвертер;
			// отсутствующие библиотеки попадают в content.Blockers.
			for _, entry := range content.Profile.Settings.Runtime.Launch.ClasspathEntries {
				row.Dependencies = append(row.Dependencies, Dependency0492{Component: d.ProfileID, Requires: entry, Kind: "classpath"})
			}
			if content.Optional != nil {
				comps := content.Optional.Catalog.Components
				edges := map[string][]string{}
				for _, component := range comps {
					for _, dep := range component.Dependencies {
						row.Dependencies = append(row.Dependencies, Dependency0492{Component: component.ID, Requires: dep.ID, Kind: "dependency"})
						edges[component.ID] = append(edges[component.ID], dep.ID)
					}
					for _, conflict := range component.Conflicts {
						row.Dependencies = append(row.Dependencies, Dependency0492{Component: component.ID, Requires: conflict.ID, Kind: "conflict"})
					}
				}
				// Циклический необязательный выбор нельзя безопасно импортировать
				// автоматически.
				state := make(map[string]int)
				var visit func(string) bool
				visit = func(node string) bool {
					if state[node] == 1 {
						return true
					}
					if state[node] == 2 {
						return false
					}
					state[node] = 1
					for _, next := range edges[node] {
						if visit(next) {
							return true
						}
					}
					state[node] = 2
					return false
				}
				for node := range edges {
					if visit(node) {
						row.Blockers = append(row.Blockers, "Циклические зависимости необязательных компонентов")
						break
					}
				}
			}
			sort.Slice(row.Dependencies, func(i, j int) bool {
				a, b := row.Dependencies[i], row.Dependencies[j]
				if a.Component != b.Component {
					return a.Component < b.Component
				}
				if a.Kind != b.Kind {
					return a.Kind < b.Kind
				}
				return a.Requires < b.Requires
			})
			plan, e := Build(run, project, target, d, inventory, compatibility, modules, content, existing[d.ProfileID], identities)
			if e != nil {
				row.Blockers = append(row.Blockers, "План завершился ошибкой: "+e.Error())
			} else {
				row.PlanSHA256, row.TransferBytes = plan.PlanSHA256, plan.TransferBytes
				row.Blockers = append(row.Blockers, plan.Blockers...)
			}
			if len(row.Blockers) == 0 {
				row.Status = "manual"
			}
		}
		sort.Strings(row.Blockers)
		row.Blockers = unique(row.Blockers)
		out.Profiles = append(out.Profiles, row)
	}
	for i := range out.Profiles {
		sort.Strings(out.Profiles[i].Blockers)
		out.Profiles[i].Blockers = unique(out.Profiles[i].Blockers)
	}
	for _, row := range out.Profiles {
		if row.Status == "blocked" {
			out.Status = "blocked"
			for _, reason := range row.Blockers {
				out.Blockers = append(out.Blockers, row.Destination.ProfilePath+": "+reason)
			}
		}
	}
	sort.Strings(out.Blockers)
	out.Blockers = unique(out.Blockers)
	out.ProfileCount = len(out.Profiles)
	var err error
	out.BatchSHA256, err = BatchDigest0492(out)
	return out, err
}
