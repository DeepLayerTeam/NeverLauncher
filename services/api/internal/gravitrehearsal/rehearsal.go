// Package gravitrehearsal проверяет доказательства из изолированного тестового
// развёртывания Gravit → Launcher под контролем оператора. Не запускается на
// промышленных ресурсах и не считает невыполненные тесты успешными.
package gravitrehearsal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

const Format = "launcher/gravit-rehearsal/v1"
const MaxReportBytes = 8 << 20

var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var economyAmount = regexp.MustCompile(`^-?[0-9]+(?:\.[0-9]{1,6})?$`)
var validUUID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

// Player — фикстура на конкретный момент времени, прочитанная ИЗ ИСТОЧНИКА и из
// изолированного тестового окружения. Дайджесты создаются из реального экспорта
// данных, а не произвольных флагов успешности. Экономика записана десятичным
// текстом во избежание потерь float.
type Player struct {
	SourceID          string `json:"sourceId"`
	UUID              string `json:"uuid"`
	InventorySHA256   string `json:"inventorySha256"`
	PermissionsSHA256 string `json:"permissionsSha256"`
	Economy           string `json:"economy"`
	SkinSHA256        string `json:"skinSha256"`
	Admin             bool   `json:"admin"`
}
type Snapshot struct {
	WorldSHA256          string   `json:"worldSha256"`
	Loader               string   `json:"loader"`
	OptionalPresetSHA256 string   `json:"optionalPresetSha256"`
	Players              []Player `json:"players"`
}
type Probe struct {
	Name           string `json:"name"`
	Passed         bool   `json:"passed"`
	RunID          string `json:"runId"`
	StageID        string `json:"stageId"`
	UUID           string `json:"uuid,omitempty"`
	EvidenceSHA256 string `json:"evidenceSha256"`
	Detail         string `json:"detail,omitempty"`
}
type LiveSession struct {
	ClientSHA256 string `json:"clientSha256"`
	PlayerName   string `json:"playerName"`
	PlayerUUID   string `json:"playerUuid"`
	BeforeSHA256 string `json:"beforeSha256"`
	JoinedSHA256 string `json:"joinedSha256"`
	StartedAt    string `json:"startedAt"`
	JoinedAt     string `json:"joinedAt"`
}

type Report struct {
	Format                string       `json:"format"`
	RunID                 string       `json:"runId"`
	StageID               string       `json:"stageId"`
	SourceInventorySHA256 string       `json:"sourceInventorySha256"`
	SourceSnapshotSHA256  string       `json:"sourceSnapshotSha256"`
	TargetSnapshotSHA256  string       `json:"targetSnapshotSha256"`
	Source                Snapshot     `json:"source"`
	Target                Snapshot     `json:"target"`
	Probes                []Probe      `json:"probes"`
	LiveSession           *LiveSession `json:"liveSession,omitempty"`
	Blockers              []string     `json:"blockers"`
	Ready                 bool         `json:"ready"`
	// Переключение остаётся неавторизованным до MIG11; репетиция не равна
	// переключению.
	CutoverAllowed bool `json:"cutoverAllowed"`
}

var RequiredProbes = []string{"launch", "login", "join", "skins", "loader", "optional", "admin"}

func SnapshotDigest(v Snapshot) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// Evaluate независимо пересчитывает готовность. Backend ОБЯЗАН вызывать его на
// переданных доказательствах, а не принимать Ready или Blockers от клиента.
func Evaluate(v Report) (Report, error) {
	if v.Format != Format || len(v.RunID) < 8 || len(v.RunID) > 128 || len(v.StageID) < 16 || len(v.StageID) > 128 || !digest.MatchString(v.SourceInventorySHA256) {
		return Report{}, errors.New("Некорректное значение: «привязка запуска, этапа и инвентаризации»")
	}
	src, e := SnapshotDigest(v.Source)
	if e != nil {
		return Report{}, e
	}
	dst, e := SnapshotDigest(v.Target)
	if e != nil {
		return Report{}, e
	}
	if v.SourceSnapshotSHA256 != src || v.TargetSnapshotSHA256 != dst {
		return Report{}, errors.New("Не совпадает контрольная сумма снимка")
	}
	blocks := []string{}
	add := func(s string) { blocks = append(blocks, s) }
	if !digest.MatchString(v.Source.WorldSHA256) || !digest.MatchString(v.Target.WorldSHA256) || v.Source.WorldSHA256 != v.Target.WorldSHA256 {
		add("Контрольная сумма снимка мира не совпадает")
	}
	if v.Source.Loader == "" || v.Source.Loader != v.Target.Loader {
		add("Несовпадение загрузчика Minecraft")
	}
	if !digest.MatchString(v.Source.OptionalPresetSHA256) || v.Source.OptionalPresetSHA256 != v.Target.OptionalPresetSHA256 {
		add("Набор необязательных компонентов отличается")
	}
	if len(v.Source.Players) == 0 || len(v.Source.Players) > 20000 || len(v.Target.Players) > 20000 {
		return Report{}, errors.New("Не поддерживается: «набор участников пробного запуска»")
	}
	indexed := map[string]Player{}
	for _, p := range v.Source.Players {
		if p.SourceID == "" || !validUUID.MatchString(p.UUID) || !digest.MatchString(p.InventorySHA256) || !digest.MatchString(p.PermissionsSHA256) || !digest.MatchString(p.SkinSHA256) || !economyAmount.MatchString(p.Economy) {
			return Report{}, errors.New("Некорректное значение: «исходный игрок»")
		}
		if _, ok := indexed[p.SourceID]; ok {
			return Report{}, errors.New("Повторяющаяся учётная запись в источнике")
		}
		indexed[p.SourceID] = p
	}
	seen := map[string]bool{}
	uuidSeen := map[string]bool{}
	for _, p := range v.Target.Players {
		if seen[p.SourceID] || uuidSeen[p.UUID] {
			return Report{}, errors.New("Обнаружен дубликат: ID целиentity/UUID")
		}
		seen[p.SourceID] = true
		uuidSeen[p.UUID] = true
		before, ok := indexed[p.SourceID]
		if !ok {
			add("Неожиданный идентификатор целевой системы")
			continue
		}
		if p.UUID != before.UUID {
			add("UUID отличается: " + p.SourceID)
		}
		if p.InventorySHA256 != before.InventorySHA256 {
			add("Содержимое инвентаря отличается: " + p.SourceID)
		}
		if p.PermissionsSHA256 != before.PermissionsSHA256 {
			add("Разрешения отличаются: " + p.SourceID)
		}
		if p.Economy != before.Economy {
			add("Данные экономики отличаются: " + p.SourceID)
		}
		if p.SkinSHA256 != before.SkinSHA256 {
			add("Скин отличается: " + p.SourceID)
		}
		if p.Admin != before.Admin {
			add("Права администратора отличаются: " + p.SourceID)
		}
	}
	for id := range indexed {
		if !seen[id] {
			add("Отсутствует игрок: " + id)
		}
	}
	if len(v.Probes) > 32 {
		return Report{}, errors.New("Превышено допустимое число проверок")
	}
	results := map[string]bool{}
	for _, p := range v.Probes {
		if p.RunID != v.RunID || p.StageID != v.StageID || p.Detail != "" || !digest.MatchString(p.EvidenceSHA256) {
			return Report{}, errors.New("Некорректное значение: «привязка свидетельств проверки»")
		}
		if _, ok := results[p.Name]; ok {
			return Report{}, errors.New("Обнаружен дубликат: проверочный запуск")
		}
		results[p.Name] = true
		if !p.Passed {
			add("Проверка завершилась ошибкой: " + p.Name)
		}
		if (p.Name == "login" || p.Name == "join") && !uuidSeen[p.UUID] {
			add("Проверка вернула неизвестный UUID: " + p.Name)
		}
	}
	for _, name := range RequiredProbes {
		if !results[name] {
			add("Отсутствует обязательная проверка: " + name)
		}
	}
	// Скрипт с результатом `passed:true` не означает живую приёмку Minecraft.
	// Требуйте от нативного CLI наблюдение клиентского процесса на переднем плане и
	// новую сессию игрока, видимую на изолированном сервере через RCON. Backend
	// проверяет внутреннюю согласованность, но не удалённую аттестацию: он всё ещё
	// доверяет оператору staging и его RCON-серверу.
	if v.LiveSession == nil {
		add("Отсутствуют доказательства нативного запуска Minecraft и подключения к работающему серверу")
	} else {
		live := v.LiveSession
		if !digest.MatchString(live.ClientSHA256) || !digest.MatchString(live.BeforeSHA256) || !digest.MatchString(live.JoinedSHA256) ||
			!validUUID.MatchString(live.PlayerUUID) || len(live.PlayerName) < 3 || len(live.PlayerName) > 16 ||
			strings.Trim(live.PlayerName, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != "" {
			return Report{}, errors.New("Некорректный формат: «свидетельство фактического запуска Minecraft»")
		}
		matched := false
		for _, p := range v.Target.Players {
			if p.UUID == live.PlayerUUID {
				matched = true
				break
			}
		}
		if !matched {
			add("UUID подключившегося игрока отсутствует среди перенесённых учётных записей")
		}
		for _, name := range []string{"login", "join"} {
			found := false
			for _, p := range v.Probes {
				if p.Name == name && p.Passed && p.UUID == live.PlayerUUID {
					found = true
					break
				}
			}
			if !found {
				add("Проверка не подтвердила личность при подключении к действующему серверу: " + name)
			}
		}
		start, e1 := time.Parse(time.RFC3339Nano, live.StartedAt)
		join, e2 := time.Parse(time.RFC3339Nano, live.JoinedAt)
		if e1 != nil || e2 != nil || !join.After(start) || join.Sub(start) > 10*time.Minute || join.Sub(start) < 2*time.Second {
			return Report{}, errors.New("Некорректное значение: «временная последовательность реального подключения»")
		}
	}
	sort.Strings(blocks)
	v.Blockers = blocks
	v.Ready = len(blocks) == 0
	v.CutoverAllowed = false
	return v, nil
}
func CompareReady(v Report) error {
	check, err := Evaluate(v)
	if err != nil {
		return err
	}
	a, _ := json.Marshal(check.Blockers)
	b, _ := json.Marshal(v.Blockers)
	if string(a) != string(b) || check.Ready != v.Ready || v.CutoverAllowed {
		return fmt.Errorf("Статус репетиционного запуска не подтверждён: %s", strings.Join(check.Blockers, "; "))
	}
	return nil
}
