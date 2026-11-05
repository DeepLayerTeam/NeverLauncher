package main

// Операции политик Guard никогда не понижают принятую эпоху и не получают
// закрытый ключ оператора. Снимки — точные подписанные конверты, а не
// восстановленные политики. Для возврата старой конфигурации требуется
// новая подпись Ed25519 на строго более высокой эпохе.
import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

const guardHistoryDir05011 = ".launcher/guard/history"

type guardHistoryItem05011 struct {
	Epoch         uint64 `json:"epoch"`
	PayloadSHA256 string `json:"payloadSha256"`
	IssuedAt      int64  `json:"issuedAt"`
	ExpiresAt     int64  `json:"expiresAt"`
	ProjectID     string `json:"projectId"`
	Minecraft     string `json:"minecraft"`
	Loader        string `json:"loader"`
	Current       bool   `json:"current"`
}

func guardHistoryName05011(v guardCompatVerified0502) string {
	return fmt.Sprintf("%020d-%s.json", v.Policy.Epoch, v.Digest)
}

func guardHistoryPersist05011(root string, raw []byte, v guardCompatVerified0502) error {
	dir, err := guardCompatPath0502(root, guardHistoryDir05011)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	file, err := guardCompatPath0502(root, guardHistoryDir05011+"/"+guardHistoryName05011(v))
	if err != nil {
		return err
	}
	// Существующие записи архива неизменяемы: никогда не перезаписывайте на месте.
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		existing, err := guardCompatRead0502(root, guardHistoryDir05011+"/"+guardHistoryName05011(v), 256*1024)
		if err != nil {
			return err
		}
		if !bytes.Equal(existing, raw) {
			return errors.New("Guard history collision/modified archived envelope")
		}
		return nil
	}
	if err != nil {
		return err
	}
	_, writeErr := f.Write(raw)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(file)
		if writeErr != nil {
			return writeErr
		}
		return closeErr
	}
	return nil
}

func guardCompatArchiveIncoming05011(root, key string, raw []byte, v guardCompatVerified0502) error {
	// Перед повышением нижней границы архивируйте предыдущую принятую политику. Если она
	// повреждена, установку нужно остановить, а не незаметно забыть доказательство.
	old, err := guardCompatRead0502(root, guardCompatPolicyFile0502, 256*1024)
	if err == nil {
		current, err := guardCompatHistoricalVerify05011(root, key, old)
		if err != nil {
			return fmt.Errorf("current Guard policy corrupt: %w", err)
		}
		floor, err := guardCompatFloorRead0502(root)
		if err != nil {
			return err
		}
		if floor == nil || floor.RootSHA256 != current.RootSHA256 || !((floor.Epoch == current.Policy.Epoch && floor.Digest == current.Digest) || (floor.Epoch == v.Policy.Epoch && floor.Digest == v.Digest)) {
			return errors.New("«current Guard policy» не совпадает с «accepted floor or interrupted install»")
		}
		if err = guardHistoryPersist05011(root, old, current); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return guardHistoryPersist05011(root, raw, v)
}

func guardHistoryRead05011(root, key string, active *guardCompatVerified0502) ([]guardHistoryItem05011, error) {
	dir, err := guardCompatPath0502(root, guardHistoryDir05011)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return []guardHistoryItem05011{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(entries) > 2048 {
		return nil, errors.New("Guard history excessive entries")
	}
	items := make([]guardHistoryItem05011, 0, len(entries))
	var currentRoot string
	if active != nil {
		currentRoot = active.RootSHA256
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") || !guardCompatRel0502(entry.Name()) || !entry.Type().IsRegular() {
			return nil, errors.New("Guard history contains unexpected entry")
		}
		raw, err := guardCompatRead0502(root, guardHistoryDir05011+"/"+entry.Name(), 256*1024)
		if err != nil {
			return nil, err
		}
		v, err := guardCompatHistoricalVerify05011(root, key, raw)
		if err != nil {
			return nil, fmt.Errorf("Некорректное значение: история Guard %s: %w", entry.Name(), err)
		}
		if guardHistoryName05011(v) != entry.Name() {
			return nil, errors.New("Несоответствие: история Guard filename/content")
		}
		if currentRoot != "" && currentRoot != v.RootSHA256 {
			return nil, errors.New("Обнаружено изменение: «Guard history trust anchor»")
		}
		items = append(items, guardHistoryItem05011{Epoch: v.Policy.Epoch, PayloadSHA256: v.Digest, IssuedAt: v.Policy.IssuedAt, ExpiresAt: v.Policy.ExpiresAt, ProjectID: v.Policy.ProjectID, Minecraft: v.Policy.Minecraft, Loader: v.Policy.Loader, Current: active != nil && active.Policy.Epoch == v.Policy.Epoch && active.Digest == v.Digest})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Epoch == items[j].Epoch {
			return items[i].PayloadSHA256 < items[j].PayloadSHA256
		}
		return items[i].Epoch > items[j].Epoch
	})
	return items, nil
}

func guardCompatHistoricalVerify05011(root, key string, raw []byte) (guardCompatVerified0502, error) {
	var env guardCompatEnvelope0502
	if err := guardCompatDecode0502(raw, &env); err != nil {
		return guardCompatVerified0502{}, err
	}
	payload, err := decodeArchivedPayload05011(env)
	if err != nil {
		return guardCompatVerified0502{}, err
	}
	return guardCompatVerifiedBytes0502(root, key, raw, time.Unix(payload.IssuedAt+1, 0))
}

func decodeArchivedPayload05011(env guardCompatEnvelope0502) (guardCompatPolicy0502, error) {
	var p guardCompatPolicy0502
	b, err := decodeGuardBase6405011(env.Payload)
	if err != nil {
		return p, err
	}
	err = guardCompatDecode0502(b, &p)
	return p, err
}
func decodeGuardBase6405011(encoded string) ([]byte, error) {
	// Ограничивайте размер чтения даже при враждебно сформированных файлах истории.
	if len(encoded) > 256*1024 {
		return nil, errors.New("Превышен допустимый размер: «history payload»")
	}
	return base64.StdEncoding.Strict().DecodeString(encoded)
}

func guardCompatAuthorizeRollback05011(root, key, file string) error {
	old, err := guardCompatLoad0502(root, key)
	if err != nil {
		return err
	}
	if old == nil {
		return errors.New("Для откат требуется «an installed signed Guard policy»")
	}
	st, err := os.Lstat(file)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > 256*1024 {
		return errors.New("Небезопасный объект: файл отката")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	newer, err := guardCompatVerifiedBytes0502(root, key, raw, time.Now())
	if err != nil {
		return err
	}
	if newer.Policy.Epoch <= old.Policy.Epoch {
		return errors.New("rollback must have a NEW signed epoch")
	}
	if newer.Policy.ProjectID != old.Policy.ProjectID || newer.Policy.Minecraft != old.Policy.Minecraft || !strings.EqualFold(newer.Policy.Loader, old.Policy.Loader) {
		return errors.New("откат: запрещено «change project/game/loader scope»")
	}
	for _, revoked := range old.Policy.RevokedDigests {
		if !hasGuardString05011(newer.Policy.RevokedDigests, revoked) {
			return errors.New("rollback attempted to undo a signed digest revocation")
		}
	}
	for _, revoked := range old.Policy.RevokedTransforms {
		if !hasGuardString05011(newer.Policy.RevokedTransforms, revoked) {
			return errors.New("rollback attempted to undo a signed transformation revocation")
		}
	}
	return nil
}
func hasGuardString05011(items []string, entry string) bool {
	for _, v := range items {
		if v == entry {
			return true
		}
	}
	return false
}

func guardCompatOperation05011(root, key string, args []string) (map[string]any, error) {
	if len(args) == 0 {
		return nil, errors.New("missing operation")
	}
	result := map[string]any{"operation": args[0], "status": "blocked", "checkedAt": time.Now().UTC().Format(time.RFC3339)}
	floor, err := guardCompatFloorRead0502(root)
	if err != nil {
		result["reason"] = "accepted_floor_invalid"
		return result, err
	}
	if floor == nil {
		result["acceptedEpoch"] = nil
	} else {
		result["acceptedEpoch"] = floor.Epoch
		result["acceptedDigest"] = floor.Digest
	}
	active, err := guardCompatLoad0502(root, key)
	if err != nil {
		result["reason"] = "signed_policy_invalid"
		return result, err
	}
	if active == nil {
		result["reason"] = "policy_not_installed"
		return result, errors.New("Guard policy not installed")
	}
	result["status"] = "pass"
	result["epoch"] = active.Policy.Epoch
	result["policySha256"] = active.Digest
	result["scope"] = map[string]string{"projectId": active.Policy.ProjectID, "minecraft": active.Policy.Minecraft, "loader": active.Policy.Loader}
	result["expiresAt"] = time.Unix(active.Policy.ExpiresAt, 0).UTC().Format(time.RFC3339)
	result["revokedDigests"] = len(active.Policy.RevokedDigests)
	result["revokedTransformations"] = len(active.Policy.RevokedTransforms)
	if args[0] == "guard-policy-history" {
		items, err := guardHistoryRead05011(root, key, active)
		if err != nil {
			result["status"] = "blocked"
			result["reason"] = "history_invalid"
			return result, err
		}
		result["items"] = items
	}
	if args[0] == "guard-policy-diagnose" {
		project := flagValue(args[1:], "--project", active.Policy.ProjectID)
		minecraft := flagValue(args[1:], "--minecraft", active.Policy.Minecraft)
		loader := flagValue(args[1:], "--loader", active.Policy.Loader)
		var agents, plugins []string
		// При проверке фактических аргументов лаунчера требуются явные пути агентов и плагинов;
		// обычный обход каталога по-прежнему проверяет подписанные моды и нативные библиотеки.
		if list := flagValue(args[1:], "--agents", ""); list != "" {
			agents = strings.Split(list, ",")
		}
		if list := flagValue(args[1:], "--plugins", ""); list != "" {
			plugins = strings.Split(list, ",")
		}
		checkErr := guardCompatValidateLaunchWithKey05011(root, key, project, minecraft, loader, agents, plugins)
		if checkErr != nil {
			result["status"] = "blocked"
			result["reason"] = "runtime_integrity_or_scope"
			result["detail"] = checkErr.Error()
			return result, checkErr
		}
		result["verifiedArtifacts"] = len(active.Policy.Artifacts)
		result["verifiedExternalNative"] = len(active.Policy.ExternalNativeModules)
		result["checkedTransformations"] = len(active.Policy.Transformations)
	}
	return result, nil
}
