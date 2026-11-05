// Package gravitplan формирует воспроизводимый предпросмотр миграции Gravit только
// на чтение по тем же проверенным источникам и конвертерам, что используются
// операциями импорта.
package gravitplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	gc "gitflic.ru/skif4er/launcher/services/api/internal/gravitcontent"
	gd "gitflic.ru/skif4er/launcher/services/api/internal/gravitdetector"
	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
	gm "gitflic.ru/skif4er/launcher/services/api/internal/gravitmodules"
)

const Format = "launcher.gravit-migration-plan.v1"

type Destination struct {
	ProfilePath   string `json:"profilePath"`
	ProfileID     string `json:"profileId"`
	ProfileName   string `json:"profileName"`
	Loader        string `json:"loader"`
	LoaderVersion string `json:"loaderVersion,omitempty"`
	Channel       string `json:"channel"`
	Version       string `json:"version"`
}
type Item struct {
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Target string `json:"target,omitempty"`
	Status string `json:"status"` // automatic, transformed, manual, blocked, excluded
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// IdentityPreview содержит только количества и причины диагностики. Пароли,
// имена пользователей, UUID и токены никогда не сохраняются в плане миграции.
type IdentityPreview struct {
	SourceAccounts         int    `json:"sourceAccounts"`
	DuplicateOrConflicting int    `json:"duplicateOrConflicting"`
	State                  string `json:"state"` // review_required | blocked
	Reason                 string `json:"reason,omitempty"`
}
type Checklist struct {
	Action   string `json:"action"`
	Detail   string `json:"detail"`
	Required bool   `json:"required"`
}
type Plan struct {
	Format          string          `json:"format"`
	RunID           string          `json:"runId"`
	ProjectID       string          `json:"projectId"`
	SourceSHA256    string          `json:"sourceSha256"`
	InventorySHA256 string          `json:"inventorySha256"`
	TargetSHA256    string          `json:"targetSha256"`
	Destination     Destination     `json:"destination"`
	DetectedVersion string          `json:"detectedVersion,omitempty"`
	Items           []Item          `json:"items"`
	Checklist       []Checklist     `json:"checklist"`
	Counts          map[string]int  `json:"counts"`
	TransferBytes   int64           `json:"transferBytes"`
	Blockers        []string        `json:"blockers"`
	Status          string          `json:"status"` // заблокировано или вручную; НИКОГДА не означает разрешения на переключение
	Content         gc.Plan         `json:"content"`
	Modules         gm.Report       `json:"modules"`
	Identities      IdentityPreview `json:"identities"`
	PlanSHA256      string          `json:"planSha256"`
}

func Digest(p Plan) (string, error) {
	p.PlanSHA256 = ""
	b, e := json.Marshal(p)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func Verify(p Plan) error {
	if p.Format != Format || len(p.PlanSHA256) != 64 {
		return errors.New("Некорректное значение: «migration plan format or digest»")
	}
	d, e := Digest(p)
	if e != nil {
		return e
	}
	if d != p.PlanSHA256 {
		return errors.New("Несоответствие: план миграции контрольная сумма")
	}
	return nil
}
func Build(runID, projectID, targetSHA string, d Destination, v inv.Inventory, c gd.Report, m gm.Report, content gc.Plan, targetProfileExists bool, identities IdentityPreview) (Plan, error) {
	if runID == "" || projectID == "" || len(targetSHA) != 64 || v.Format != inv.Format || c.Format != "launcher.gravit-compatibility.v1" || m.Format != gm.Format || v.SourceSHA256 != c.SourceSHA256 || v.SourceSHA256 != m.SourceSHA256 || v.ManifestSHA256 != m.InventorySHA256 || content.SourceSHA256 != v.SourceSHA256 || content.InventorySHA256 != v.ManifestSHA256 || content.ProfilePath != d.ProfilePath || content.Profile.Profile.ID != d.ProfileID || content.Profile.Profile.ProjectID != projectID || content.Profile.Settings.Minecraft.LoaderVersion != d.LoaderVersion {
		return Plan{}, errors.New("Несовпадение: «source, target or content preview»")
	}
	if _, e := v.Manifest(); e != nil {
		return Plan{}, e
	}
	p := Plan{Format: Format, RunID: runID, ProjectID: projectID, SourceSHA256: v.SourceSHA256, InventorySHA256: v.ManifestSHA256, TargetSHA256: targetSHA, Destination: d, DetectedVersion: c.DetectedVersion, Items: []Item{}, Checklist: []Checklist{}, Counts: map[string]int{"automatic": 0, "transformed": 0, "manual": 0, "blocked": 0, "excluded": 0}, Blockers: []string{}, Content: content, Modules: m, Identities: identities, Status: "manual"}
	add := func(item Item) {
		p.Items = append(p.Items, item)
		p.Counts[item.Status]++
		if item.Status == "automatic" || item.Status == "transformed" {
			p.TransferBytes += item.Bytes
		}
		if item.Status == "blocked" {
			p.Blockers = append(p.Blockers, fmt.Sprintf("%s: %s", item.Source, item.Reason))
		}
	}
	transferred := map[string]gc.File{}
	for _, f := range content.Files {
		transferred[f.SourcePath] = f
	}
	skipped := map[string]string{}
	for _, f := range content.SkippedFiles {
		skipped[f.SourcePath] = f.Reason
	}
	for _, f := range v.Files {
		row := Item{Kind: f.Kind, Source: f.Path, Bytes: f.Size, SHA256: f.SHA256, Status: "manual"}
		switch f.Kind {
		case "client_profile":
			if f.Path == d.ProfilePath {
				row.Status = "transformed"
				row.Target = d.ProfileID
				row.Reason = "Настройки профиля преобразованы действующим конвертером; сборка релиза и запуск игры ещё необходимы"
			} else {
				row.Reason = "Профиль не выбран: настройте и предварительно проверьте каждый профиль до переключения"
			}
		case "asset", "client", "library":
			if reason, ok := skipped[f.Path]; ok {
				row.Status = "excluded"
				row.Reason = reason
			} else if t, ok := transferred[f.Path]; ok {
				row.Status = "automatic"
				row.Target = t.TargetPath
				row.Reason = "file SHA-256 pinned to source inventory"
			} else {
				row.Reason = "Файл не входит в выбранный профиль; отдельно проверьте принадлежность и импорт"
			}
		case "module", "module_config", "server_wrapper":
			row.Reason = "Проверьте замену модуля или регистрацию ServerBridge; сторонний JAR не запускается"
		case "authentication":
			row.Reason = "Сопоставление учётных записей, UUID и проверочных хешей паролей требует отдельной подтверждённой предварительной проверки"
		case "texture":
			row.Reason = "Для текстуры необходимы проверенный импорт источника или провайдера и проверка отображения в Minecraft"
		case "key":
			row.Status = "excluded"
			row.Reason = "Старые закрытые ключи и доверенные учётные данные нельзя импортировать; замените их в целевой системе"
		case "launchserver", "runtime":
			row.Reason = "Настройки необходимо задать и проверить в Never; секреты автоматически не переносятся"
		default:
			row.Reason = "Источник не классифицирован; оператор должен принять решение до переключения"
		}
		add(row)
	}
	for _, f := range c.Findings {
		if f.Severity == "blocked" {
			p.Blockers = append(p.Blockers, fmt.Sprintf("compatibility %s (%s): %s", f.Code, f.Path, f.Message))
		}
	}
	for _, f := range m.Modules {
		if f.Status == "blocked" {
			p.Blockers = append(p.Blockers, "module "+f.Path+": "+f.Reason)
		}
	}
	for _, w := range m.Wrappers {
		if w.Status == "blocked" {
			p.Blockers = append(p.Blockers, "wrapper "+w.Path+": "+w.Reason)
		}
	}
	for _, b := range m.Blockers {
		p.Blockers = append(p.Blockers, "modules: "+b)
	}
	for _, b := range content.Blockers {
		p.Blockers = append(p.Blockers, "content: "+b)
	}
	if !content.Ready {
		p.Blockers = append(p.Blockers, "Выбранный профиль невозможно импортировать текущим конвертером")
	}
	if identities.State != "review_required" || identities.DuplicateOrConflicting > 0 || identities.SourceAccounts == 0 {
		p.Blockers = append(p.Blockers, "identities: "+identities.Reason)
	}
	if targetProfileExists {
		p.Blockers = append(p.Blockers, "Целевой идентификатор профиля уже существует; выберите новый или явно разрешите конфликт")
	}
	if c.Status == "blocked" || c.VersionStatus == "unsupported" || c.VersionStatus == "conflict" {
		p.Blockers = append(p.Blockers, "Анализ совместимости Gravit заблокирован")
	}
	if len(p.Blockers) > 0 {
		p.Status = "blocked"
	}
	p.Checklist = []Checklist{
		{"verify_source", "При импорте повторно загрузите исходный ZIP; SHA-256 источника и манифест должны совпадать", true},
		{"resolve_manual", "Проверьте невыбранные профили, неизвестные файлы, дополнительные условия и замены модулей", true},
		{"verify_uuid", "Сопоставьте UUID каждой учётной записи с данными игрока, правами и инвентарём; конфликты UUID устраните вручную", true},
		{"reset_credentials", "Замените ключи лаунчера, устройств, ServerBridge и прокси; предусмотрите сброс неподдерживаемых хешей паролей", true},
		{"textures", "Повторно импортируйте проверенные скины и плащи и убедитесь в корректном отображении при выбранном способе авторизации", true},
		{"rehearse", "Соберите подписанный целевой релиз и подтвердите настоящий запуск клиента, подключение к серверу и сохранность данных", true},
		{"backup_and_rollback", "Создайте резервные копии источника и миров, проверьте восстановление, согласуйте простой, блокировку записи и точку отката", true},
	}
	sort.Slice(p.Items, func(i, j int) bool { return p.Items[i].Source < p.Items[j].Source })
	sort.Strings(p.Blockers)
	p.Blockers = unique(p.Blockers)
	digest, e := Digest(p)
	if e != nil {
		return Plan{}, e
	}
	p.PlanSHA256 = digest
	return p, nil
}
func unique(values []string) []string {
	o := values[:0]
	for _, v := range values {
		if len(o) == 0 || o[len(o)-1] != v {
			o = append(o, v)
		}
	}
	return o
}
