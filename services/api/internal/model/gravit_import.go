package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Преобразование Gravit никогда не скачивает файлы, не выполняет действия и не
// доверяет чужому classloader. Выходные настройки предназначены для НОВОГО рабочего
// пространства Never; обычный цикл подготовки, проверки, подписи и публикации
// остаётся обязательным.
var gravitJavaClass02210 = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)+$`)

type GravitFieldResult02210 struct {
	Field  string `json:"field"`
	Status string `json:"status"` // mapped, transformed, manual, blocked
	Target string `json:"target,omitempty"`
	Reason string `json:"reason"`
}
type GravitServer02210 struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	Default bool   `json:"default"`
}
type GravitBuildSettings02210 struct {
	Minecraft    MinecraftInfo     `json:"minecraft"`
	Runtime      RuntimeInfo       `json:"runtime"`
	Directories  Directories       `json:"directories"`
	FileRules    []FileRule        `json:"fileRules"`
	ToolVersions map[string]string `json:"toolVersions"`
}
type GravitImportResult02210 struct {
	Format       string                   `json:"format"`
	SourceSHA256 string                   `json:"sourceSha256"`
	Ready        bool                     `json:"ready"`
	Profile      Profile                  `json:"profile"`
	Settings     GravitBuildSettings02210 `json:"settings"`
	Servers      []GravitServer02210      `json:"servers"`
	Fields       []GravitFieldResult02210 `json:"fields"`
	Summary      map[string]int           `json:"summary"`
}

// ConvertGravitProfile02210 принимает один JSON ClientProfile. Оператор должен
// заранее преобразовать JSONC в корректный JSON: удалять комментарии внутри
// строковых литералов без парсера небезопасно. Пустые и неизвестные поля никогда не
// исчезают молча. SourceSHA256 определяет точные проанализированные входные байты.
func ConvertGravitProfile02210(source []byte, projectID, profileID, profileName, loaderHint string) (GravitImportResult02210, error) {
	if len(source) == 0 || len(source) > 1<<20 {
		return GravitImportResult02210{}, errors.New("Размер Gravit ClientProfile должен быть от 1 байта до 1 МиБ")
	}
	root, err := gravitObject02210(source)
	if err != nil {
		return GravitImportResult02210{}, err
	}
	if len(root) == 0 {
		return GravitImportResult02210{}, errors.New("Gravit ClientProfile пуст")
	}
	sum := sha256.Sum256(source)
	out := GravitImportResult02210{Format: "launcher.gravit-import-report.v1", SourceSHA256: hex.EncodeToString(sum[:]), Servers: []GravitServer02210{}, Fields: []GravitFieldResult02210{}, Summary: map[string]int{"mapped": 0, "transformed": 0, "manual": 0, "blocked": 0}}
	report := func(field, status, target, reason string) {
		out.Fields = append(out.Fields, GravitFieldResult02210{field, status, target, reason})
		out.Summary[status]++
	}
	stringField := func(field string) (string, bool) {
		raw, ok := root[field]
		if !ok {
			return "", false
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			report(field, "blocked", "", "expected a string")
			return "", false
		}
		return s, true
	}
	integerField := func(field string) (int, bool) {
		raw, ok := root[field]
		if !ok {
			return 0, false
		}
		var n int
		if err := json.Unmarshal(raw, &n); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			report(field, "blocked", "", "Ожидается целое число")
			return 0, false
		}
		return n, true
	}
	listField := func(field string) ([]string, bool) {
		raw, ok := root[field]
		if !ok {
			return nil, false
		}
		var v []string
		if err := json.Unmarshal(raw, &v); err != nil || v == nil {
			report(field, "blocked", "", "Ожидается массив строк")
			return nil, false
		}
		if len(v) > 4096 {
			report(field, "blocked", "", "Превышено допустимое количество элементов")
			return nil, false
		}
		return v, true
	}
	title, ok := stringField("title")
	if ok {
		report("title", "mapped", "profile.name", "Отображаемое название")
	}
	if title == "" {
		report("title", "blocked", "profile.name", "Необходимо указать непустое название")
	}
	desc, ok := stringField("info")
	if ok {
		report("info", "mapped", "profile.description", "Отображаемое описание")
	}
	if profileName == "" {
		profileName = title
	}
	if len(profileName) > 120 || len(desc) > 4096 {
		return GravitImportResult02210{}, errors.New("Слишком длинное название или описание профиля")
	}
	if projectID == "" || !profileID0225.MatchString(profileID) || profileID == "." || profileID == ".." {
		return GravitImportResult02210{}, errors.New("Требуются идентификатор целевого проекта и безопасный идентификатор нового профиля")
	}
	version, ok := stringField("version")
	if ok {
		report("version", "mapped", "settings.minecraft.version", "Версия Minecraft")
	}
	if version == "" {
		report("version", "blocked", "settings.minecraft.version", "Необходимо указать версию Minecraft")
	}
	out.Settings.Minecraft.Version = version
	mainClass, ok := stringField("mainClass")
	if ok {
		out.Settings.Runtime.Launch.MainClass = mainClass
		report("mainClass", "mapped", "settings.runtime.launch.mainClass", "Точка входа Java")
	}
	if !gravitJavaClass02210.MatchString(mainClass) {
		report("mainClass", "blocked", "settings.runtime.launch.mainClass", "Необходимо корректное полное имя главного класса Java")
	}
	out.Settings.Runtime.Launch.ClasspathStrategy = "manifest"
	out.Settings.Runtime.Java.Distribution = "temurin"
	if loaderHint == "" {
		loaderHint = "vanilla"
		report("loaderHint", "manual", "profile.loader", "Подтвердите загрузчик (Gravit ClientProfile не указывает его идентификатор)")
	}
	switch loaderHint {
	case "vanilla", "fabric", "quilt", "forge", "neoforge":
	default:
		report("loaderHint", "blocked", "profile.loader", "Указан неподдерживаемый загрузчик")
	}
	out.Settings.Minecraft.Loader = loaderHint
	out.Profile = Profile{ID: profileID, ProjectID: projectID, Name: profileName, Description: desc, Loader: loaderHint, Preset: "custom"}
	if p, e := NormalizeProfileV2(out.Profile); e == nil {
		out.Profile = p
	} else {
		report("destination", "blocked", "profile", e.Error())
	}
	if v, ok := stringField("uuid"); ok {
		if len(v) < 8 || len(v) > 64 {
			report("uuid", "blocked", "", "Некорректный UUID исходного профиля")
		} else {
			report("uuid", "transformed", "sourceSha256", "UUID источника не используется в качестве идентификатора профиля Never")
		}
	}
	if v, ok := stringField("dir"); ok {
		if !gravitSafePath02210(v) {
			report("dir", "blocked", "", "Небезопасный каталог установки в источнике")
		} else {
			report("dir", "manual", "", "Каталог источника выбирается при импорте рабочей области, а не как путь к файлу клиента")
		}
	}
	if v, ok := stringField("assetDir"); ok {
		if !gravitSafePath02210(v) {
			report("assetDir", "blocked", "", "Небезопасный каталог ресурсов")
		} else {
			out.Settings.Directories.Assets = v
			report("assetDir", "mapped", "settings.directories.assets", "Каталог ресурсов")
		}
	}
	if v, ok := stringField("assetIndex"); ok {
		if v == "" {
			report("assetIndex", "blocked", "", "Индекс ресурсов пуст")
		} else {
			report("assetIndex", "manual", "", "При подготовке ресурсов Minecraft необходимо указать метаданные индекса ресурсов")
		}
	}
	if v, ok := integerField("sortIndex"); ok {
		if v == 0 {
			report("sortIndex", "mapped", "", "Позиция сортировки по умолчанию")
		} else {
			report("sortIndex", "manual", "", "Never Profile v2 не поддерживает постоянный индекс сортировки")
		}
	}
	for _, key := range []string{"minJavaVersion", "recommendJavaVersion", "maxJavaVersion"} {
		if v, ok := integerField(key); ok {
			if v < 0 || (v > 255 && !(key == "maxJavaVersion" && v == 999)) {
				report(key, "blocked", "", "Основная версия Java вне поддерживаемого диапазона")
				continue
			}
			target := "settings.runtime.java."
			status := "mapped"
			reason := "Ограничение версии Java"
			switch key {
			case "minJavaVersion":
				out.Settings.Runtime.Java.MinimumMajorVersion = v
				target += "minimumMajorVersion"
			case "recommendJavaVersion":
				out.Settings.Runtime.Java.RecommendedMajorVersion = v
				out.Settings.Runtime.Java.MajorVersion = v
				target += "recommendedMajorVersion"
			case "maxJavaVersion":
				target += "maximumMajorVersion"
				if v == 999 {
					status = "transformed"
					reason = "Неограниченное значение 999 в Gravit сопоставлено с максимальным значением 0 в Never"
				} else {
					out.Settings.Runtime.Java.MaximumMajorVersion = v
				}
			}
			report(key, status, target, reason)
		}
	}
	java := &out.Settings.Runtime.Java
	if java.MajorVersion == 0 {
		java.MajorVersion = java.MinimumMajorVersion
	}
	if java.MajorVersion == 0 {
		report("recommendJavaVersion", "blocked", "settings.runtime.java.majorVersion", "Необходимо явно указать основную версию Java")
	}
	if v, ok := root["warnMissJavaVersion"]; ok {
		var b bool
		if json.Unmarshal(v, &b) != nil || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			report("warnMissJavaVersion", "blocked", "", "Ожидается логическое значение")
		} else if b {
			report("warnMissJavaVersion", "manual", "", "Never принудительно проверяет ограничения Java, а не продолжает работу с предупреждением")
		} else {
			report("warnMissJavaVersion", "transformed", "settings.runtime.java", "Never принудительно проверяет ограничения Java")
		}
	}
	for _, key := range []string{"jvmArgs", "clientArgs"} {
		if values, ok := listField(key); ok {
			if key == "jvmArgs" {
				check := Manifest{Runtime: RuntimeInfo{Java: JavaInfo{MajorVersion: 17, Distribution: "temurin"}, JVMArgs: values}}
				if e := ValidateRuntimeConstraints0223(check); e != nil {
					report(key, "blocked", "settings.runtime.jvmArgs", e.Error())
					continue
				}
				out.Settings.Runtime.JVMArgs = values
				report(key, "mapped", "settings.runtime.jvmArgs", "Порядок аргументов JVM сохранён; дополнительные аргументы должен одобрить издатель проекта")
			} else {
				unsafe := ""
				protected := map[string]bool{"--accesstoken": true, "--uuid": true, "--username": true, "--usertype": true, "--xuid": true, "--clientid": true, "--gamedir": true, "--assetsdir": true}
				for _, arg := range values {
					lower := strings.ToLower(arg)
					if strings.ContainsAny(arg, "\x00\r\n") || protected[strings.SplitN(lower, "=", 2)[0]] {
						unsafe = arg
						break
					}
				}
				if unsafe != "" {
					report(key, "blocked", "settings.minecraft.gameArgs", "Зарезервированный или небезопасный аргумент запуска Minecraft: "+unsafe)
					continue
				}
				out.Settings.Minecraft.GameArgs = values
				report(key, "mapped", "settings.minecraft.gameArgs", "Порядок аргументов клиента сохранён; аргументами авторизации и сеанса управляет Runtime")
			}
		}
	}
	for _, key := range []string{"classPath", "altClassPath"} {
		if v, ok := listField(key); ok {
			if key == "altClassPath" && len(v) > 0 {
				report(key, "blocked", "", "Альтернативный системный список классов Gravit не эквивалентен подписанному списку Never")
				continue
			}
			if key == "altClassPath" {
				report(key, "mapped", "", "Альтернативный путь к классам пуст")
				continue
			}
			good := true
			seenPaths := map[string]bool{}
			for _, entry := range v {
				normalized := strings.ToLower(entry)
				if seenPaths[normalized] {
					report(key, "blocked", "", "Повторяющаяся запись пути к классам: "+entry)
					good = false
					break
				}
				seenPaths[normalized] = true
				if !gravitSafePath02210(entry) || gravitProtected02210(entry) {
					report(key, "blocked", "", "Небезопасная запись пути к классам: "+entry)
					good = false
					break
				}
				if !strings.HasSuffix(strings.ToLower(entry), ".jar") {
					report(key, "blocked", "", "Для каталога или файла не в формате JAR необходимо перечислить подписанные JAR-файлы: "+entry)
					good = false
					break
				}
			}
			if good {
				out.Settings.Runtime.Launch.ClasspathEntries = v
				report(key, "transformed", "settings.runtime.launch.classpathEntries", "Упорядоченный список JAR: перед публикацией каждый файл должен быть подготовлен с SHA-256")
			}
		}
	}
	if _, ok := root["classLoaderConfig"]; !ok {
		report("classLoaderConfig", "blocked", "", "Загрузчик классов должен быть задан явно; нельзя считать поведение Gravit по умолчанию эквивалентным Never")
	}
	if raw, ok := root["classLoaderConfig"]; ok {
		var v string
		if json.Unmarshal(raw, &v) != nil {
			report("classLoaderConfig", "blocked", "", "Ожидается строка")
		} else if v == "SYSTEM_ARGS" {
			report("classLoaderConfig", "transformed", "settings.runtime.launch", "Нативный запуск процесса JVM: необходимо подтвердить эквивалентность главного класса и загрузки")
		} else {
			report("classLoaderConfig", "blocked", "", "Неподдерживаемый загрузчик классов Gravit: "+v+"; Never не будет выполнять начальную загрузку стороннего лаунчера")
		}
	}
	for _, key := range []string{"compatClasses", "updateOptional"} {
		if raw, ok := root[key]; ok {
			var list []json.RawMessage
			if json.Unmarshal(raw, &list) != nil || list == nil {
				report(key, "blocked", "", "Ожидается массив")
			} else if len(list) > 0 {
				for i, item := range list {
					field := fmt.Sprintf("%s[%d]", key, i)
					if key == "updateOptional" {
						var option map[string]json.RawMessage
						if json.Unmarshal(item, &option) == nil {
							if actions, found := option["actions"]; found {
								var values []json.RawMessage
								if json.Unmarshal(actions, &values) == nil {
									for j, a := range values {
										var action map[string]json.RawMessage
										if json.Unmarshal(a, &action) == nil {
											var kind string
											_ = json.Unmarshal(action["type"], &kind)
											report(fmt.Sprintf("%s.actions[%d]", field, j), "blocked", "", "Неподдерживаемое необязательное действие: "+kind+"; требуется ручной перенос с сохранением зависимостей и конфликтов")
										}
									}
								}
							}
						}
					}
					report(field, "blocked", "", "Дополнительные действия или запуск совместимости нельзя безопасно воспроизвести")
				}
			} else {
				report(key, "mapped", "", "Пустой массив")
			}
		}
	}
	// Политика файлов преобразуется консервативно: verify никогда не разрешает
	// удаление отсутствующих в манифесте файлов, даже для каталогов Gravit update.
	policy := map[string]FileRule{}
	for _, key := range []string{"update", "updateVerify", "updateExclusions"} {
		v, ok := listField(key)
		if !ok {
			continue
		}
		valid := true
		for _, raw := range v {
			pattern, good := gravitFilePattern02210(raw)
			if !good {
				report(key, "blocked", "", "Небезопасное правило обработки файла: "+raw)
				valid = false
				continue
			}
			if key != "updateExclusions" && gravitProtected02210(raw) {
				report(key, "blocked", "", "Gravit пытается обновить путь, принадлежащий пользователю: "+raw)
				valid = false
				continue
			}
			rule := FileRule{Pattern: pattern, Action: "verify", Ownership: "required"}
			if key == "updateExclusions" {
				rule = FileRule{Pattern: pattern, Action: "exclude", Ownership: "user-owned"}
			}
			if prior, exists := policy[pattern]; exists && prior.Action != rule.Action {
				report(key, "blocked", "", "Конфликт принадлежности по пути "+pattern)
				valid = false
				continue
			}
			policy[pattern] = rule
		}
		if valid {
			status := "transformed"
			target := "settings.fileRules"
			reason := "Управляемое обновление Gravit преобразовано в безопасные правила проверки Never; требуются фактические хеши"
			if key == "updateExclusions" {
				reason = "Исключения преобразованы в защиту файлов, принадлежащих пользователю"
			}
			if len(v) == 0 {
				status = "mapped"
				reason = "Список правил файлов пуст"
			}
			report(key, status, target, reason)
		}
	}
	keys := make([]string, 0, len(policy))
	for k := range policy {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out.Settings.FileRules = append(out.Settings.FileRules, policy[k])
	}
	if len(out.Settings.FileRules) > 0 {
		probe := Manifest{SchemaVersion: ManifestSchemaV2, FileRules: out.Settings.FileRules}
		if err := ValidateFileOwnership0224(probe); err != nil {
			report("fileRules", "blocked", "settings.fileRules", err.Error())
		}
	}
	if raw, ok := root["settings"]; ok {
		fields, e := gravitObject02210(raw)
		if e != nil {
			report("settings", "blocked", "", "Ожидается объект настроек")
		} else {
			for k, v := range fields {
				switch k {
				case "ram":
					var n int
					if json.Unmarshal(v, &n) != nil || bytes.Equal(bytes.TrimSpace(v), []byte("null")) || n < 0 || n > 1048576 {
						report("settings.ram", "blocked", "", "Объём RAM должен быть неотрицательным целым числом")
					} else {
						out.Settings.Runtime.Memory.RecommendedMb = n
						report("settings.ram", "transformed", "settings.runtime.memory.recommendedMb", "Ноль означает автоматический выбор")
					}
				case "autoEnter", "fullScreen":
					var b bool
					if json.Unmarshal(v, &b) != nil || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
						report("settings."+k, "blocked", "", "Ожидается логическое значение")
					} else if b {
						report("settings."+k, "manual", "", "Настройки рабочей области сборки не могут принудительно менять предпочтения пользователя Desktop")
					} else {
						report("settings."+k, "mapped", "", "По умолчанию отключено; переопределять настройки рабочей области не требуется")
					}
				default:
					report("settings."+k, "blocked", "", "Неизвестный параметр настроек")
				}
			}
		}
	}
	if raw, ok := root["servers"]; ok {
		var servers []map[string]json.RawMessage
		if json.Unmarshal(raw, &servers) != nil || servers == nil {
			report("servers", "blocked", "", "Ожидается массив серверов")
		} else {
			if len(servers) > 128 {
				report("servers", "blocked", "", "Превышено допустимое количество серверов")
			} else if len(servers) == 0 {
				report("servers", "mapped", "", "Пустой список")
			} else {
				defaults := 0
				for i, s := range servers {
					label := fmt.Sprintf("servers[%d]", i)
					var name, address string
					var port int
					var d bool
					if json.Unmarshal(s["name"], &name) != nil || json.Unmarshal(s["serverAddress"], &address) != nil || json.Unmarshal(s["serverPort"], &port) != nil || name == "" || address == "" || port < 1 || port > 65535 {
						report(label, "blocked", "", "Необходимо указать имя сервера, адрес и допустимый TCP-порт")
						continue
					}
					if v, has := s["isDefault"]; has && json.Unmarshal(v, &d) != nil {
						report(label, "blocked", "", "isDefault должен иметь логическое значение")
						continue
					}
					if d {
						defaults++
					}
					for k := range s {
						switch k {
						case "name", "serverAddress", "serverPort", "isDefault", "protocol", "socketPing":
						default:
							report(label+"."+k, "blocked", "", "Неизвестный режим работы сервера")
						}
					}
					out.Servers = append(out.Servers, GravitServer02210{Name: name, Address: address, Port: port, Default: d})
					report(label, "manual", "serverBrowser", "Создайте сервер Never ServerBridge в рамках проекта и профиля; записи серверов Gravit напрямую в реестр не импортируются")
				}
				if defaults > 1 {
					report("servers", "blocked", "", "Указано несколько серверов по умолчанию")
				}
			}
		}
	}
	if raw, ok := root["limited"]; ok {
		var limited bool
		if json.Unmarshal(raw, &limited) != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			report("limited", "blocked", "", "Ожидается логическое значение")
		} else if limited {
			report("limited", "blocked", "", "Ограничение разрешений Gravit требует явных ACL Never; импорт сам по себе не выдаёт доступ")
		} else {
			report("limited", "mapped", "", "Исходный профиль не имеет ограничений")
		}
	}
	if raw, ok := root["properties"]; ok {
		var p map[string]json.RawMessage
		if json.Unmarshal(raw, &p) != nil || p == nil {
			report("properties", "blocked", "", "Ожидался объект")
		} else if len(p) > 0 {
			report("properties", "manual", "", "Пользовательские свойства требуют отдельной проверки влияния на запуск и аутентификацию")
		} else {
			report("properties", "mapped", "", "Нет пользовательских свойств")
		}
	}
	known := map[string]bool{}
	for _, k := range []string{"title", "uuid", "version", "info", "dir", "sortIndex", "assetIndex", "assetDir", "update", "updateExclusions", "updateVerify", "updateOptional", "jvmArgs", "classPath", "altClassPath", "clientArgs", "compatClasses", "properties", "servers", "classLoaderConfig", "recommendJavaVersion", "minJavaVersion", "maxJavaVersion", "warnMissJavaVersion", "settings", "limited", "mainClass"} {
		known[k] = true
	}
	for k := range root {
		if !known[k] {
			report(k, "blocked", "", "Неизвестное поле Gravit: нельзя молча пропускать возможное влияние на запуск или безопасность")
		}
	}
	// Предпросмотр может содержать пути classpath, ещё отсутствующие в его перечне
	// файлов. Проверяйте остальное тем же промышленным валидатором, что и при
	// публикации.
	runtimeProbe := out.Settings.Runtime
	runtimeProbe.Launch.ClasspathEntries = nil
	check := Manifest{SchemaVersion: ManifestSchemaV2, Runtime: runtimeProbe, Minecraft: out.Settings.Minecraft}
	if err := ValidateRuntimeConstraints0223(check); err != nil {
		report("runtime", "blocked", "settings.runtime", err.Error())
	}
	sort.Slice(out.Fields, func(i, j int) bool {
		if out.Fields[i].Field == out.Fields[j].Field {
			return out.Fields[i].Status < out.Fields[j].Status
		}
		return out.Fields[i].Field < out.Fields[j].Field
	})
	out.Ready = out.Summary["blocked"] == 0 && out.Summary["manual"] == 0
	return out, nil
}

func gravitObject02210(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tok, e := d.Token()
	if e != nil || tok != json.Delim('{') {
		return nil, errors.New("Gravit ClientProfile должен быть объектом JSON")
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		tok, e = d.Token()
		if e != nil {
			return nil, e
		}
		k, ok := tok.(string)
		if !ok {
			return nil, errors.New("Недопустимый ключ объекта")
		}
		if _, exists := out[k]; exists {
			return nil, fmt.Errorf("Повторяющееся поле JSON %q", k)
		}
		var v json.RawMessage
		if e = d.Decode(&v); e != nil {
			return nil, e
		}
		out[k] = v
	}
	if _, e = d.Token(); e != nil {
		return nil, e
	}
	var tail json.RawMessage
	if e = d.Decode(&tail); e != nil && e != io.EOF {
		return nil, errors.New("Неожиданные данные после JSON")
	}
	if len(tail) != 0 {
		return nil, errors.New("Неожиданное дополнительное значение после JSON")
	}
	return out, nil
}
func gravitSafePath02210(s string) bool {
	if s == "" || len(s) > 512 || strings.ContainsAny(s, "\\:\x00\r\n*?[]") || strings.HasPrefix(s, "/") || path.Clean(s) != s || s == "." || s == ".." || strings.HasPrefix(s, "../") {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}
func gravitFilePattern02210(s string) (string, bool) {
	if !gravitSafePath02210(s) {
		return "", false
	}
	if strings.HasSuffix(strings.ToLower(s), ".jar") || strings.Contains(path.Base(s), ".") {
		return s, true
	}
	return s + "/**", true
}

func gravitProtected02210(s string) bool { return protectedFilePath0224(s) }
