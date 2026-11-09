package main

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Общее хранилище с адресацией по содержимому явно настраивает оператор. Ключом
// служит проверенный SHA-1 источника, а каждое установленное содержимое также
// фиксируется по SHA-256 в InstallPlan. Файлы кэша всегда копируются, а не
// связываются с изменяемыми игровыми каталогами.
type sharedArtifactsKey0277 struct{}
type sharedArtifacts0277 struct{ root string }

func sharedArtifactsFromContext0277(ctx context.Context) *sharedArtifacts0277 {
	c, _ := ctx.Value(sharedArtifactsKey0277{}).(*sharedArtifacts0277)
	return c
}

func sharedArtifactsContext0277(ctx context.Context, cacheDir, clientDir string) (context.Context, error) {
	if strings.TrimSpace(cacheDir) == "" {
		return ctx, nil
	}
	root, err := filepath.Abs(cacheDir)
	if err != nil {
		return ctx, err
	}
	client, err := filepath.Abs(clientDir)
	if err != nil {
		return ctx, err
	}
	if pathContained0277(root, client) || pathContained0277(client, root) {
		return ctx, errors.New("общий кеш и каталог клиента: запрещено «пересечение»")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return ctx, err
	}
	st, err := os.Lstat(root)
	if err != nil {
		return ctx, err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return ctx, errors.New("Для корневого каталога общего кэша требуется обычный каталог")
	}
	return context.WithValue(ctx, sharedArtifactsKey0277{}, &sharedArtifacts0277{root: root}), nil
}
func pathContained0277(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))))
}
func eligibleSharedArtifact0277(kind string) bool {
	switch kind {
	case "asset", "library", "native-archive", "loader-library", "forge-library", "installer-embedded-library":
		return true
	}
	return false
}
func (c *sharedArtifacts0277) locate(sha string) (string, error) {
	if !validSHA1Hex(sha) {
		return "", errors.New("Для общего кэша требуется проверенная контрольная сумма SHA-1")
	}
	sha = strings.ToLower(sha)
	return secureClientDestination(c.root, "sha1/"+sha[:2]+"/"+sha)
}

// restore проверяет всю запись кэша до копирования; неверная запись или объект не
// являющийся обычным файлом — ошибка, а не попадание в кэш.
func (c *sharedArtifacts0277) restore(ctx context.Context, dst, sha string, expectedSize int64) (bool, string, int64, error) {
	src, err := c.locate(sha)
	if err != nil {
		return false, "", 0, err
	}
	st, err := os.Lstat(src)
	if errors.Is(err, os.ErrNotExist) {
		return false, "", 0, nil
	}
	if err != nil {
		return false, "", 0, err
	}
	if !st.Mode().IsRegular() {
		return false, "", 0, fmt.Errorf("Некорректный объект кеша %s", sha)
	}
	if expectedSize > 0 && st.Size() != expectedSize {
		return false, "", 0, fmt.Errorf("Несовпадение: размер артефакта в кеше: %s", sha)
	}
	valid, digest, size := existingFileMatchesSHA1(src, sha, expectedSize)
	if !valid {
		return false, "", 0, fmt.Errorf("Несовпадение: контрольная сумма артефакта в кеше: %s", sha)
	}
	if err := ctx.Err(); err != nil {
		return false, "", 0, err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return false, "", 0, err
	}
	temp, err := os.CreateTemp(filepath.Dir(dst), ".nl-cas-*")
	if err != nil {
		return false, "", 0, err
	}
	defer os.Remove(temp.Name())
	in, err := os.Open(src)
	if err != nil {
		temp.Close()
		return false, "", 0, err
	}
	h1, h256 := sha1.New(), sha256.New()
	copied, cpErr := io.Copy(io.MultiWriter(temp, h1, h256), &contextReader0277{ctx: ctx, r: in})
	closeIn := in.Close()
	syncErr := temp.Sync()
	closeOut := temp.Close()
	if cpErr != nil {
		return false, "", 0, cpErr
	}
	if closeIn != nil {
		return false, "", 0, closeIn
	}
	if syncErr != nil {
		return false, "", 0, syncErr
	}
	if closeOut != nil {
		return false, "", 0, closeOut
	}
	if copied != size || !strings.EqualFold(hex.EncodeToString(h1.Sum(nil)), sha) || hex.EncodeToString(h256.Sum(nil)) != digest {
		return false, "", 0, errors.New("Общий кеш изменился во время восстановления")
	}
	if err := replaceFileAtomicPortable(temp.Name(), dst); err != nil {
		return false, "", 0, err
	}
	return true, digest, size, nil
}

// store использует закрытый временный файл и атомарную жёсткую ссылку «создать, если отсутствует» внутри
// кэша. Конкурирующие сборки не могут опубликовать частично записанные байты.
func (c *sharedArtifacts0277) store(ctx context.Context, source, sha, digest string, expectedSize int64) error {
	dst, err := c.locate(sha)
	if err != nil {
		return err
	}
	if !isSHA256Hex0271(digest) {
		return errors.New("Некорректное значение: SHA-256 входного файла общего кеша")
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return err
	}
	if info, e := os.Lstat(dst); e == nil {
		if !info.Mode().IsRegular() {
			return errors.New("В общем кеше найден элемент, не являющийся обычным файлом")
		}
		ok, got, size := existingFileMatchesSHA1(dst, sha, expectedSize)
		if !ok || got != digest || size != expectedSize {
			return fmt.Errorf("Некорректное значение: существующая запись общего кеша: %s", sha)
		}
		return nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	temp, err := os.CreateTemp(filepath.Dir(dst), ".nl-cas-store-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	h1, h256 := sha1.New(), sha256.New()
	copied, copyErr := io.Copy(io.MultiWriter(temp, h1, h256), &contextReader0277{ctx: ctx, r: input})
	syncErr := temp.Sync()
	closeErr := temp.Close()
	if copyErr != nil {
		return copyErr
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	if copied != expectedSize || !strings.EqualFold(hex.EncodeToString(h1.Sum(nil)), sha) || hex.EncodeToString(h256.Sum(nil)) != digest {
		return errors.New("Входные данные общего кеша не прошли проверку целостности")
	}
	err = os.Link(temp.Name(), dst)
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrExist) {
		return err
	}
	// Другой исполнитель выиграл гонку. Проверьте его артефакт независимо.
	info, e := os.Lstat(dst)
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() {
		return errors.New("Параллельно созданный элемент кеша не является обычным файлом")
	}
	ok, other, size := existingFileMatchesSHA1(dst, sha, expectedSize)
	if !ok || other != digest || size != expectedSize {
		return errors.New("Несовпадение: целостность записи кеша при одновременном доступе")
	}
	return nil
}

type contextReader0277 struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader0277) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
func unionNativeTargets0277(a, b []vanillaTarget) []vanillaTarget {
	seen := map[string]vanillaTarget{}
	for _, target := range append(append([]vanillaTarget{}, a...), b...) {
		seen[target.OS+"/"+target.Arch] = target
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]vanillaTarget, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return out
}
func equalStringSets0277(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	a = append([]string{}, a...)
	b = append([]string{}, b...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Отклоняйте две разные ревизии одной библиотеки Java на заданной цели. Нативные файлы по
// classifier намеренно исключены: это артефакты ОС/архитектуры, а не дополнительные
// версии classpath. Проверка выполняется до загрузок.
func validateVanillaLibraryConflicts0277(libraries []MojangLibrary, targets []vanillaTarget) error {
	for _, target := range targets {
		selected := map[string]string{}
		for _, lib := range libraries {
			if !rulesAllowTarget(lib.Rules, target) || !libraryArtifactAppliesToTarget(lib.Name, target) || isClassifiedNativeLibrary(lib.Name) {
				continue
			}
			parts := strings.Split(strings.TrimSpace(lib.Name), ":")
			if len(parts) < 3 {
				continue
			} // первоначальная проверка позднее отклонит некорректные координаты
			key := parts[0] + ":" + parts[1]
			if previous, ok := selected[key]; ok && previous != parts[2] {
				return fmt.Errorf("Несовместимые библиотеки Minecraft %s:%s и %s для платформы %s/%s", key, previous, parts[2], target.OS, target.Arch)
			}
			selected[key] = parts[2]
		}
	}
	return nil
}
