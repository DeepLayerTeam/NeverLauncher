package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// GravitOptionalMigration02411 — преобразование для проверки владельцем, НИКОГДА не
// доверенный релиз. Ссылаться можно только на уже захешированные файлы
// необязательных компонентов черновика. После импорта обязательны обычные
// предпросмотр каталога, CAS-сохранение и подпись релиза.
type GravitOptionalMigration02411 struct {
	Format       string                   `json:"format"`
	SourceSHA256 string                   `json:"sourceSha256"`
	Ready        bool                     `json:"ready"`
	Catalog      ComponentCatalog0241     `json:"catalog"`
	Fields       []GravitFieldResult02210 `json:"fields"`
	Summary      map[string]int           `json:"summary"`
}

var gravitSlug02411 = regexp.MustCompile(`[^a-z0-9]+`)

func gravitID02411(prefix, name string) string {
	s := strings.Trim(gravitSlug02411.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if s == "" {
		s = "component"
	}
	if len(s) > 70 {
		s = strings.TrimRight(s[:70], "-")
	}
	sum := sha256.Sum256([]byte(name))
	return prefix + s + "-" + hex.EncodeToString(sum[:4])
}

func gravitArray02411(raw json.RawMessage) ([]json.RawMessage, error) {
	var v []json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &v) != nil || v == nil {
		return nil, errors.New("Ожидался массив, отличный от null")
	}
	return v, nil
}
func gravitString02411(raw json.RawMessage) (string, bool) {
	var s string
	return s, json.Unmarshal(raw, &s) == nil && bytes.TrimSpace(raw)[0] == '"'
}
func gravitBool02411(raw json.RawMessage) (bool, bool) {
	var b bool
	e := json.Unmarshal(raw, &b)
	return b, e == nil && (bytes.Equal(raw, []byte("true")) || bytes.Equal(raw, []byte("false")))
}
func gravitInt02411(raw json.RawMessage) (int, bool) {
	var n int
	e := json.Unmarshal(raw, &n)
	return n, e == nil && len(raw) > 0 && (raw[0] == '-' || (raw[0] >= '0' && raw[0] <= '9')) && !bytes.ContainsAny(raw, ".eE")
}

// ConvertGravitOptionalView02411 преобразует updateOptional из Gravit ClientProfile
// либо явный массив OptionalFile. Здесь нет сети и загрузок, подписания, выдачи прав
// или исполнения чужих команд. Неизвестная семантика не отбрасывается молча:
// Ready=false, а несовместимости перечисляются.
func ConvertGravitOptionalView02411(source []byte, base ComponentCatalog0241, signedFiles []ManifestFile) (GravitOptionalMigration02411, error) {
	if len(source) == 0 || len(source) > 1<<20 {
		return GravitOptionalMigration02411{}, errors.New("Размер необязательного источника Gravit должен быть от 1 байта до 1 МиБ")
	}
	sum := sha256.Sum256(source)
	out := GravitOptionalMigration02411{Format: "launcher.gravit-optional-migration.v1", SourceSHA256: hex.EncodeToString(sum[:]), Fields: []GravitFieldResult02210{}, Summary: map[string]int{"mapped": 0, "transformed": 0, "manual": 0, "blocked": 0}}
	note := func(field, status, target, reason string) {
		out.Fields = append(out.Fields, GravitFieldResult02210{Field: field, Status: status, Target: target, Reason: reason})
		out.Summary[status]++
	}
	var raw json.RawMessage
	if bytes.HasPrefix(bytes.TrimSpace(source), []byte("[")) {
		raw = source
	} else {
		root, e := gravitObject02210(source)
		if e != nil {
			return out, e
		}
		raw = root["updateOptional"]
		if len(raw) == 0 {
			return out, errors.New("В Gravit ClientProfile отсутствует updateOptional")
		}
	}
	entries, e := gravitArray02411(raw)
	if e != nil {
		return out, fmt.Errorf("updateOptional: %w", e)
	}
	if len(entries) > 4096 {
		return out, errors.New("Слишком много необязательных записей Gravit")
	}
	// Никогда не перезаписывайте существующие компоненты и не меняйте владельца
	// существующего файла.
	cat := base
	cat.Components = append([]CatalogComponent0241(nil), base.Components...)
	cat.Categories = append([]CatalogCategory0242(nil), base.Categories...)
	cat.Groups = append([]CatalogGroup0242(nil), base.Groups...)
	cat.Presets = append([]CatalogPreset0242(nil), base.Presets...)
	cat.SchemaVersion = ComponentCatalogSchema0245
	if cat.Revision == 0 {
		cat.Revision = 1
	}
	fileMap := map[string]string{}
	for _, f := range signedFiles {
		if FileOwnership0224(f) == "optional" && !f.Required && len(f.SHA256) == 64 {
			fileMap[strings.ToLower(f.Path)] = f.Path
		}
	}
	owned := map[string]bool{}
	for _, c := range cat.Components {
		for _, p := range c.Files {
			owned[strings.ToLower(p)] = true
		}
	}
	existingIDs := map[string]bool{}
	for _, c := range cat.Components {
		existingIDs[c.ID] = true
	}
	categories := map[string]bool{}
	for _, c := range cat.Categories {
		categories[c.ID] = true
	}
	names := map[string]string{}
	opts := make([]map[string]json.RawMessage, len(entries))
	for i, entry := range entries {
		label := fmt.Sprintf("updateOptional[%d]", i)
		obj, err := gravitObject02210(entry)
		if err != nil {
			note(label, "blocked", "", err.Error())
			continue
		}
		opts[i] = obj
		name, ok := gravitString02411(obj["name"])
		if !ok || strings.TrimSpace(name) == "" || len(name) > 256 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
			note(label+".name", "blocked", "", "Требуется непустое допустимое имя")
			continue
		}
		if _, dup := names[name]; dup {
			note(label+".name", "blocked", "", "Повторяющееся имя Gravit")
			continue
		}
		id := gravitID02411("gravit-", name)
		if existingIDs[id] {
			note(label+".name", "blocked", "", "Устойчивый идентификатор уже существует в каталоге")
			continue
		}
		names[name] = id
		existingIDs[id] = true
	}
	for i, obj := range opts {
		if obj == nil {
			continue
		}
		label := fmt.Sprintf("updateOptional[%d]", i)
		name, ok := gravitString02411(obj["name"])
		if !ok || names[name] == "" {
			continue
		}
		id := names[name]
		c := CatalogComponent0241{ID: id, Name: name, Version: "1.0.0", Files: []string{}, Visible: func() *bool { b := true; return &b }()}
		note(label+".name", "transformed", "components."+id+".id", "Постоянный идентификатор получен из точного имени Gravit; версия 1.0.0 используется как значение при миграции")
		known := map[string]bool{"name": true, "info": true, "mark": true, "visible": true, "limited": true, "permissions": true, "category": true, "subTreeLevel": true, "dependenciesFile": true, "conflictFile": true, "triggersList": true, "triggers": true, "actions": true, "groupFile": true, "isPreset": true}
		if raw, has := obj["groupFile"]; has && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			entries, err := gravitArray02411(raw)
			if err != nil || len(entries) != 0 {
				note(label+".groupFile", "blocked", "", "Gravit groupFile требует выбора хотя бы одного варианта; проверьте взаимоисключающие группы вручную")
			}
		}
		if raw, has := obj["isPreset"]; has {
			b, ok := gravitBool02411(raw)
			if !ok || b {
				note(label+".isPreset", "blocked", "", "Семантика выбора Gravit isPreset отличается от пресетов Never")
			}
		}
		for key := range obj {
			if !known[key] {
				note(label+"."+key, "blocked", "", "Неизвестная семантика необязательного компонента Gravit")
			}
		}
		if v, has := obj["info"]; has && !bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			if s, ok := gravitString02411(v); ok && len(s) <= 4096 {
				c.Description = s
				note(label+".info", "mapped", "components."+id+".description", "description")
			} else {
				note(label+".info", "blocked", "", "Недопустимое описание")
			}
		}
		for _, field := range []string{"mark", "visible", "limited"} {
			if v, has := obj[field]; has {
				b, ok := gravitBool02411(v)
				if !ok {
					note(label+"."+field, "blocked", "", "Ожидается логическое значение")
					continue
				}
				switch field {
				case "mark":
					c.Default = b
				case "visible":
					*c.Visible = b
				case "limited":
					c.Limited = b
					if b {
						note(label+".limited", "blocked", "", "Маску разрешений Gravit нельзя импортировать как подтверждённые права Never")
						continue
					}
				}
				note(label+"."+field, "mapped", "components."+id+"."+field, "Логический атрибут выбора")
			}
		}
		if v, has := obj["permissions"]; has {
			n, ok := gravitInt02411(v)
			if !ok || n != 0 {
				note(label+".permissions", "blocked", "", "Битовая маска разрешений Gravit не может предоставлять права Never")
			} else {
				note(label+".permissions", "mapped", "", "Нулевые разрешения")
			}
		}
		if v, has := obj["category"]; has && !bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			s, ok := gravitString02411(v)
			if !ok || len(s) > 120 || strings.IndexFunc(s, unicode.IsControl) >= 0 {
				note(label+".category", "blocked", "", "Недопустимая категория")
			} else if s != "" && !strings.EqualFold(s, "GLOBAL") {
				cid := gravitID02411("gravit-category-", s)
				c.CategoryID = cid
				if !categories[cid] {
					cat.Categories = append(cat.Categories, CatalogCategory0242{ID: cid, Name: s})
					categories[cid] = true
				}
				note(label+".category", "transformed", "categories."+cid, "Название категории сохранено")
			}
		}
		if v, has := obj["subTreeLevel"]; has {
			n, ok := gravitInt02411(v)
			if !ok || n < 0 || n > 32 {
				note(label+".subTreeLevel", "blocked", "", "Недопустимый уровень вложенности")
			} else if n > 1 {
				note(label+".subTreeLevel", "manual", "groups", "Визуальный отступ не определяет родительскую сущность; проверьте вложенные группы")
			}
		}
		for _, rel := range []struct {
			key        string
			dependency bool
		}{{"dependenciesFile", true}, {"conflictFile", false}} {
			if v, has := obj[rel.key]; has && !bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
				list, err := gravitArray02411(v)
				if err != nil {
					note(label+"."+rel.key, "blocked", "", err.Error())
					continue
				}
				for j, rr := range list {
					fld := fmt.Sprintf("%s.%s[%d]", label, rel.key, j)
					r, e := gravitObject02210(rr)
					if e != nil {
						note(fld, "blocked", "", e.Error())
						continue
					}
					for k := range r {
						if k != "name" {
							note(fld+"."+k, "blocked", "", "Неподдерживаемый атрибут отношения")
						}
					}
					rn, ok := gravitString02411(r["name"])
					rid := names[rn]
					if !ok || rid == "" {
						note(fld, "blocked", "", "Название зависимости или конфликта отсутствует в этом импорте")
						continue
					}
					if rel.dependency {
						c.Dependencies = append(c.Dependencies, ComponentRequirement0243{ID: rid})
					} else {
						c.Conflicts = append(c.Conflicts, ComponentRequirement0243{ID: rid})
					}
					note(fld, "mapped", "components."+id, "Постоянный идентификатор определён по точному имени источника")
				}
			}
		}
		if v, has := obj["triggers"]; has && !bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			a, err := gravitArray02411(v)
			if err != nil || len(a) > 0 {
				note(label+".triggers", "blocked", "", "Семантика устаревших триггеров не поддерживается; используйте распознаваемый triggersList")
			}
		}
		if v, has := obj["triggersList"]; has && !bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			a, err := gravitArray02411(v)
			if err != nil {
				note(label+".triggersList", "blocked", "", err.Error())
			} else {
				cond := ComponentConditions0244{SchemaVersion: "1.0"}
				seen := map[string]bool{}
				for j, rawTrigger := range a {
					fld := fmt.Sprintf("%s.triggersList[%d]", label, j)
					t, e := gravitObject02210(rawTrigger)
					if e != nil {
						note(fld, "blocked", "", e.Error())
						continue
					}
					kind, ok := gravitString02411(t["type"])
					kind = strings.ToLower(kind)
					required, rok := gravitBool02411(t["required"])
					inverted, iok := false, true
					if raw, has := t["inverted"]; has {
						inverted, iok = gravitBool02411(raw)
					}
					if !ok || !rok || !iok || !required || inverted || seen[kind] {
						note(fld, "blocked", "", "Только отдельные обязательные, неинвертированные условия os/java/arch сохраняют семантику доступности Never")
						continue
					}
					seen[kind] = true
					allowed := map[string]bool{"type": true, "required": true, "inverted": true}
					switch kind {
					case "os":
						allowed["os"] = true
						v, valid := gravitString02411(t["os"])
						switch strings.ToUpper(v) {
						case "MUSTDIE":
							cond.OS = []string{"windows"}
						case "LINUX":
							cond.OS = []string{"linux"}
						case "MACOSX":
							cond.OS = []string{"macos"}
						default:
							valid = false
						}
						if !valid {
							note(fld, "blocked", "", "Неподдерживаемая ОС Gravit")
							continue
						}
					case "arch":
						allowed["arch"] = true
						v, valid := gravitString02411(t["arch"])
						switch strings.ToUpper(v) {
						case "X86_64":
							cond.Arch = []string{"x86_64"}
						case "AARCH64":
							cond.Arch = []string{"aarch64"}
						default:
							valid = false
						}
						if !valid {
							note(fld, "blocked", "", "Неподдерживаемая архитектура Gravit")
							continue
						}
					case "java":
						allowed["minVersion"] = true
						allowed["maxVersion"] = true
						min, okMin := 8, true
						if raw, has := t["minVersion"]; has {
							min, okMin = gravitInt02411(raw)
						}
						max, okMax := 999, true
						if raw, has := t["maxVersion"]; has {
							max, okMax = gravitInt02411(raw)
						}
						allowed["requireJavaFX"] = true
						if raw, has := t["requireJavaFX"]; has {
							fx, ok := gravitBool02411(raw)
							if !ok || fx {
								note(fld, "blocked", "", "Требование JavaFX Runtime нельзя проверить как условие Never")
								continue
							}
						}
						if !okMin || !okMax || min < 0 || max < 0 || min > 99 || max > 999 || (max != 999 && max != 0 && max < min) {
							note(fld, "blocked", "", "Недопустимый диапазон основных версий Java")
							continue
						}
						cond.JavaMajorMin = uint32(min)
						if max != 999 {
							cond.JavaMajorMax = uint32(max)
						}
					default:
						note(fld, "blocked", "", "Неподдерживаемый тип триггера")
						continue
					}
					for k := range t {
						if !allowed[k] {
							note(fld+"."+k, "blocked", "", "Неизвестное поле условия срабатывания")
						}
					}
					note(fld, "transformed", "components."+id+".conditions", "Обязательный триггер сопоставлен с подписанным условием доступности")
				}
				if len(cond.OS) > 0 || len(cond.Arch) > 0 || cond.JavaMajorMin > 0 || cond.JavaMajorMax > 0 {
					c.Conditions = &cond
				}
			}
		}
		if v, has := obj["actions"]; has {
			actions, e := gravitArray02411(v)
			if e != nil {
				note(label+".actions", "blocked", "", e.Error())
			} else if len(actions) > 64 {
				note(label+".actions", "blocked", "", "Слишком много необязательных действий")
			} else {
				type classPath02411 struct {
					field string
					paths []string
				}
				pendingCP := []classPath02411{}
				for j, ra := range actions {
					fld := fmt.Sprintf("%s.actions[%d]", label, j)
					a, e := gravitObject02210(ra)
					if e != nil {
						note(fld, "blocked", "", e.Error())
						continue
					}
					typ, ok := gravitString02411(a["type"])
					if !ok {
						note(fld, "blocked", "", "Отсутствует тип действия")
						continue
					}
					lower := strings.ToLower(typ)
					switch lower {
					case "file", "classpath":
						if lower == "classpath" {
							// У Gravit OptionalActionClassPath есть args: List<String> и useAltClasspath.
							// Never поддерживает только основной classpath.
							for k := range a {
								if k != "type" && k != "args" && k != "useAltClasspath" {
									note(fld+"."+k, "blocked", "", "Неизвестный атрибут действия с путём к классам")
								}
							}
							var paths []string
							if json.Unmarshal(a["args"], &paths) != nil || len(paths) == 0 || len(paths) > 64 {
								note(fld, "blocked", "", "Недопустимые аргументы classpath")
								continue
							}
							if v, has := a["useAltClasspath"]; has {
								alt, ok := gravitBool02411(v)
								if !ok || alt {
									note(fld, "blocked", "", "Альтернативный системный classpath не эквивалентен подписанному classpath Never")
									continue
								}
							}
							pendingCP = append(pendingCP, classPath02411{field: fld, paths: paths})
							continue
						}
						for k := range a {
							if k != "type" && k != "files" {
								note(fld+"."+k, "blocked", "", "Неподдерживаемое поле файлового действия")
							}
						}
						rawFiles := a["files"]
						if len(rawFiles) == 0 {
							note(fld, "blocked", "", "Отсутствует карта файлов")
							continue
						}
						fm, e := gravitObject02210(rawFiles)
						if e != nil || len(fm) == 0 {
							note(fld, "blocked", "", "Ожидалась непустая карта путей к файлам")
							continue
						}
						paths := make([]string, 0, len(fm))
						for p := range fm {
							paths = append(paths, p)
						}
						sort.Strings(paths)
						for _, sourcePath := range paths {
							v, ok := gravitString02411(fm[sourcePath])
							if !ok {
								note(fld+".files."+sourcePath, "blocked", "", "Путь назначения файла должен быть строкой")
								continue
							}
							if v != "" && v != sourcePath {
								note(fld+".files."+sourcePath, "blocked", "", "Нельзя подтвердить, что перенос или переименование файла сохраняет эквивалентность подписанному управляемому владению")
								continue
							}
							if !gravitSafePath02210(sourcePath) || gravitProtected02210(sourcePath) {
								note(fld+".files."+sourcePath, "blocked", "", "Небезопасный или защищённый путь источника")
								continue
							}
							exact := fileMap[strings.ToLower(sourcePath)]
							if exact != sourcePath || owned[strings.ToLower(sourcePath)] {
								note(fld+".files."+sourcePath, "blocked", "", "Файл не подготовлен как неподконтрольный подписанный дополнительный путь в черновике пакета")
								continue
							}
							c.Files = append(c.Files, sourcePath)
							c.Actions = append(c.Actions, ComponentAction0245{Type: "File", Path: sourcePath})
							owned[strings.ToLower(sourcePath)] = true
							note(fld+".files."+sourcePath, "mapped", "components."+id+".actions", "Привязано к фактическому SHA-256 необязательного файла в черновике выпуска")
						}
					case "jvmargs", "clientargs":
						for k := range a {
							if k != "type" && k != "args" {
								note(fld+"."+k, "blocked", "", "Неизвестное поле действия с аргументами")
							}
						}
						var args []string
						if json.Unmarshal(a["args"], &args) != nil || len(args) == 0 || len(args) > 32 {
							note(fld, "blocked", "", "Недопустимый массив аргументов")
							continue
						}
						kind := "JvmArgs"
						if lower == "clientargs" {
							kind = "ClientArgs"
						}
						valid := true
						for _, arg := range args {
							if !safeOptionalArgument0245(kind, arg) {
								valid = false
							}
						}
						if !valid {
							note(fld, "blocked", "", "Небезопасный или неподдерживаемый аргумент Never; выполнение команд и переопределение аутентификации запрещены")
							continue
						}
						c.Actions = append(c.Actions, ComponentAction0245{Type: kind, Args: args})
						note(fld, "mapped", "components."+id+".actions", "Безопасное подписанное действие с аргументами")
					default:
						note(fld, "blocked", "", "Неподдерживаемый тип дополнительного действия "+typ)
					}
				}
				for _, cp := range pendingCP {
					for _, p := range cp.paths {
						found := false
						for _, ownedPath := range c.Files {
							if ownedPath == p {
								found = true
								break
							}
						}
						if !found || !strings.HasSuffix(strings.ToLower(p), ".jar") {
							note(cp.field, "blocked", "", "Элементы classpath требуют подписанный JAR, принадлежащий тому же компоненту: "+p)
							continue
						}
						c.Actions = append(c.Actions, ComponentAction0245{Type: "ClassPath", Path: p})
						note(cp.field, "mapped", "components."+id+".actions", "Основной путь к классам привязан к подписанному JAR, принадлежащему проекту")
					}
				}
			}
		}
		if len(c.Files) == 0 {
			note(label, "blocked", "", "Для компонентов Never требуется один или несколько подготовленных подписанных дополнительных файлов")
		}
		cat.Components = append(cat.Components, c)
	}
	for _, f := range signedFiles {
		if FileOwnership0224(f) == "optional" && !owned[strings.ToLower(f.Path)] {
			note("files."+f.Path, "blocked", "", "У подготовленного дополнительного файла нет компонента-владельца; назначьте его в редакторе до подписания")
		}
	}
	cat = NewComponentCatalog0245(cat, base.Revision+1)
	sort.Slice(out.Fields, func(i, j int) bool {
		if out.Fields[i].Field == out.Fields[j].Field {
			return out.Fields[i].Status < out.Fields[j].Status
		}
		return out.Fields[i].Field < out.Fields[j].Field
	})
	out.Catalog = cat
	out.Ready = out.Summary["blocked"] == 0 && out.Summary["manual"] == 0
	return out, nil
}
