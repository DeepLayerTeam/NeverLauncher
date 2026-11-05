package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SecurityGeneration принадлежит подписанному манифесту набора компонентов. Его НЕЛЬЗЯ
// выводить из productVersion, URL зеркала или ID локальной транзакции. Контрольное
// минимальное значение хранится вне управляемого дерева компонентов, подверженного откату.
// Все вызовы сериализованы существующей блокировкой транзакционного обновлятора.
const componentSecurityState02311 = ".launcher/component-security"

type componentGenerationRecord02311 struct {
	Schema         uint32 `json:"schema"`
	Generation     uint64 `json:"generation"`
	ManifestDigest string `json:"manifestDigest"`
}

func componentSecurityRequired02311(v string) bool {
	a, b, c, ok := parseCoreVersion(v)
	return ok && (a > 0 || b > 23 || (b == 23 && c >= 11))
}

func componentDigest02311(m componentUpdateManifest0157) string {
	raw, _ := json.Marshal(m)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func loadComponentWatermark02311(root string) (componentGenerationRecord02311, error) {
	var found bool
	var current componentGenerationRecord02311
	for i := 0; i < 2; i++ {
		path := filepath.Join(root, fmt.Sprintf("%s-%d.json", componentSecurityState02311, i))
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return current, err
		}
		found = true
		if !info.Mode().IsRegular() || info.Size() > 4096 {
			return current, errors.New("Некорректное значение: слот поколения компонентов: файл не является обычным или превышает допустимый размер")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return current, err
		}
		var item componentGenerationRecord02311
		if json.Unmarshal(raw, &item) != nil || item.Schema != 1 || item.Generation == 0 || len(item.ManifestDigest) != 64 {
			return current, errors.New("Повреждена запись поколения безопасности компонентов")
		}
		if _, err := hex.DecodeString(item.ManifestDigest); err != nil {
			return current, errors.New("Повреждена контрольная сумма поколения компонентов")
		}
		if item.Generation > current.Generation {
			current = item
		} else if item.Generation == current.Generation && current.ManifestDigest != item.ManifestDigest {
			return current, errors.New("Обнаружен конфликт записей поколения безопасности компонентов")
		}
	}
	if found && current.Generation == 0 {
		return current, errors.New("Повреждена отметка безопасности компонентов; понижение версии запрещено")
	}
	return current, nil
}

func writeComponentWatermark02311(root string, item componentGenerationRecord02311) error {
	if item.Generation == 0 {
		return nil
	}
	old, err := loadComponentWatermark02311(root)
	if err != nil {
		return err
	}
	if old.Generation > item.Generation {
		return errors.New("Нельзя понизить отметку уровня безопасности компонентов")
	}
	if old.Generation == item.Generation {
		if old.ManifestDigest != item.ManifestDigest {
			return errors.New("Обнаружены противоречивые данные о поколении компонентов")
		}
		return nil
	}
	item.Schema = 1
	dest := filepath.Join(root, fmt.Sprintf("%s-%d.json", componentSecurityState02311, item.Generation%2))
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	return writeJSONFileAtomicMode(dest, item, 0o600)
}

func checkComponentGeneration02311(root string, m componentUpdateManifest0157) error {
	floor, err := loadComponentWatermark02311(root)
	if err != nil {
		return err
	}
	if m.SecurityGeneration < floor.Generation {
		return fmt.Errorf("Защита компонентов от отката: подписанное поколение %d ниже ранее принятого %d", m.SecurityGeneration, floor.Generation)
	}
	if m.SecurityGeneration == floor.Generation && floor.Generation > 0 && componentDigest02311(m) != floor.ManifestDigest {
		return errors.New("Поколение компонентов повторно использовано для другого подписанного набора")
	}
	// Проверенное установленное состояние может опережать контрольное минимальное значение, если
	// питание пропало после атомарной фиксации, но до сохранения отдельного значения.
	statePath := filepath.Join(root, filepath.FromSlash(componentUpdateStateFile0157))
	st, available, err := readComponentUpdateStateOptional01510(statePath)
	if err != nil {
		return err
	}
	if available && st.SecurityGeneration > m.SecurityGeneration {
		return fmt.Errorf("Защита компонентов от отката: установленное поколение %d выше предлагаемого %d", st.SecurityGeneration, m.SecurityGeneration)
	}
	if available && st.SecurityGeneration == m.SecurityGeneration && st.SecurityGeneration > 0 && st.ManifestDigest != componentDigest02311(m) {
		return errors.New("Предлагаемый набор конфликтует с установленным поколением безопасности компонентов")
	}
	return nil
}

func commitComponentGeneration02311(root string, m componentUpdateManifest0157) error {
	if m.SecurityGeneration == 0 {
		return nil
	}
	path := filepath.Join(root, filepath.FromSlash(componentUpdateStateFile0157))
	st, present, err := readComponentUpdateStateOptional01510(path)
	if err != nil {
		return err
	}
	if !present || st.SecurityGeneration != m.SecurityGeneration || st.ManifestDigest != componentDigest02311(m) {
		return errors.New("Нельзя записать поколение, пока зафиксированное состояние компонентов не соответствует подписанному набору")
	}
	return writeComponentWatermark02311(root, componentGenerationRecord02311{Generation: st.SecurityGeneration, ManifestDigest: st.ManifestDigest})
}

func reconcileInstalledComponentGeneration02311(root string) error {
	path := filepath.Join(root, filepath.FromSlash(componentUpdateStateFile0157))
	st, present, err := readComponentUpdateStateOptional01510(path)
	if err != nil {
		return err
	}
	floor, err := loadComponentWatermark02311(root)
	if err != nil {
		return err
	}
	if !present {
		if floor.Generation > 0 {
			return errors.New("Состояние безопасности компонентов отсутствует после принятия поколения")
		}
		return nil
	}
	if st.SecurityGeneration < floor.Generation {
		return errors.New("Поколение установленного набора компонентов ниже отметки безопасности")
	}
	if st.SecurityGeneration == floor.Generation && floor.Generation > 0 && st.ManifestDigest != floor.ManifestDigest {
		return errors.New("Манифест установленных компонентов не совпадает с отметкой безопасности")
	}
	if st.SecurityGeneration == 0 {
		return nil
	}
	if !componentSecurityRequired02311(st.Version) || len(st.ManifestDigest) != 64 || strings.TrimSpace(st.ManifestDigest) == "" {
		return errors.New("Неверный формат состояния поколения безопасности установленных компонентов")
	}
	if st.SecurityGeneration > floor.Generation {
		// Никогда не повышайте нижнюю границу на основе одного непроверенного локального
		// состояния. Активное дерево компонентов должно соответствовать всем записанным SHA-256.
		verifyRoot := root
		if st.Platform == "macos" {
			if filepath.Base(st.BundleName) != st.BundleName || !strings.HasSuffix(strings.ToLower(st.BundleName), ".app") {
				return errors.New("В состоянии безопасности компонентов отсутствует либо небезопасно имя активного пакета macOS")
			}
			verifyRoot = filepath.Join(root, st.BundleName)
			info, err := os.Lstat(verifyRoot)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("Активный пакет компонентов macOS не является доверенным каталогом")
			}
		}
		for _, item := range append(append([]componentUpdateArtifact0157{}, st.Components...), st.SupportFiles...) {
			if err := validateComponentRelativePath0157(item.TargetPath); err != nil {
				return err
			}
			full := filepath.Join(verifyRoot, filepath.FromSlash(item.TargetPath))
			info, err := os.Lstat(full)
			if err != nil || !info.Mode().IsRegular() {
				return fmt.Errorf("путь компонента %s отсутствует или: требуется обычный файл", item.Component)
			}
			if err := verifyUpdaterFile0156(full, item.Size, item.SHA256); err != nil {
				return fmt.Errorf("Нельзя согласовать непроверенный установленный компонент %s: %w", item.Component, err)
			}
		}
		return writeComponentWatermark02311(root, componentGenerationRecord02311{Generation: st.SecurityGeneration, ManifestDigest: st.ManifestDigest})
	}
	return nil
}
