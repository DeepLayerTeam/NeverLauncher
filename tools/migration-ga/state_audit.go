package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Дисковое сравнение независимо изолированных снимков Minecraft-проектов.
// Оба корня должны содержать world/, plugins/ и player-uuids.txt. Аудитор
// читает реальные байты; хеши от вызывающего не могут скрыть несовпадающие данные.
const stateAuditFormat = "never/gravit-state-audit/v1"
const stateMaxFiles = 150000
const stateMaxBytes int64 = 1 << 40
const stateMaxFile int64 = 32 << 30

var canonicalUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type StateAudit struct {
	Format             string   `json:"format"`
	Matched            bool     `json:"matched"`
	SourceWorldSHA256  string   `json:"sourceWorldSha256"`
	TargetWorldSHA256  string   `json:"targetWorldSha256"`
	SourcePluginSHA256 string   `json:"sourcePluginSha256"`
	TargetPluginSHA256 string   `json:"targetPluginSha256"`
	SourceUUIDs        []string `json:"sourceUuids"`
	TargetUUIDs        []string `json:"targetUuids"`
	WorldFiles         int      `json:"worldFiles"`
	PluginFiles        int      `json:"pluginFiles"`
	// Исключения строго ограничены временным файлом блокировки Minecraft.
	Excluded []string `json:"excluded"`
}

type treeDigest struct {
	hash     string
	files    int
	excluded []string
}

func stateTree(root, child string) (treeDigest, error) {
	var result treeDigest
	dir := filepath.Join(root, child)
	stat, err := os.Lstat(dir)
	if err != nil {
		return result, err
	}
	if !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 {
		return result, errors.New("state snapshot tree must be a real directory")
	}
	paths := make([]string, 0, 128)
	err = filepath.WalkDir(dir, func(p string, entry os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in snapshot: %s", p)
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("nonregular snapshot member: %s", p)
		}
		rel, e := filepath.Rel(dir, p)
		if e != nil || rel == "." || filepath.IsAbs(rel) {
			return errors.New("invalid snapshot member")
		}
		if child == "world" && rel == "session.lock" {
			result.excluded = append(result.excluded, filepath.ToSlash(filepath.Join(child, rel)))
			return nil
		}
		paths = append(paths, rel)
		if len(paths) > stateMaxFiles {
			return errors.New("Слишком много файлов снимка")
		}
		return nil
	})
	if err != nil {
		return result, err
	}
	if len(paths) == 0 && child == "world" {
		return result, errors.New("empty Minecraft world tree")
	}
	sort.Strings(paths)
	h := sha256.New()
	total := int64(0)
	for _, rel := range paths {
		p := filepath.Join(dir, rel)
		before, err := os.Lstat(p)
		if err != nil {
			return result, err
		}
		if !before.Mode().IsRegular() || before.Size() > stateMaxFile || before.Size() < 0 {
			return result, fmt.Errorf("invalid snapshot file %s", rel)
		}
		total += before.Size()
		if total > stateMaxBytes {
			return result, errors.New("snapshot exceeds total byte limit")
		}
		f, err := os.Open(p)
		if err != nil {
			return result, err
		}
		afterOpen, err := f.Stat()
		if err != nil || !afterOpen.Mode().IsRegular() || !os.SameFile(before, afterOpen) {
			f.Close()
			return result, fmt.Errorf("snapshot file replaced: %s", rel)
		}
		fh := sha256.New()
		n, err := io.Copy(fh, io.LimitReader(f, before.Size()+1))
		after, statErr := f.Stat()
		closeErr := f.Close()
		if err != nil || statErr != nil || closeErr != nil || n != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
			return result, fmt.Errorf("snapshot file changed during audit: %s", rel)
		}
		// Стабильное кадровое кодирование исключает коллизии конкатенации path+content.
		pathBytes := []byte(filepath.ToSlash(rel))
		if err = binary.Write(h, binary.BigEndian, uint32(len(pathBytes))); err != nil {
			return result, err
		}
		h.Write(pathBytes)
		if err = binary.Write(h, binary.BigEndian, uint64(n)); err != nil {
			return result, err
		}
		h.Write(fh.Sum(nil))
	}
	result.hash = hex.EncodeToString(h.Sum(nil))
	result.files = len(paths)
	return result, nil
}

func stateRoster(root string) ([]string, error) {
	p := filepath.Join(root, "player-uuids.txt")
	info, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 8<<20 {
		return nil, errors.New("invalid UUID roster")
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(io.LimitReader(f, (8<<20)+1))
	seen := map[string]bool{}
	uuids := []string{}
	for scanner.Scan() {
		id := strings.TrimSpace(scanner.Text())
		if !canonicalUUID.MatchString(id) || seen[id] {
			return nil, errors.New("invalid or duplicated player UUID in roster")
		}
		seen[id] = true
		uuids = append(uuids, id)
		if len(uuids) > 200000 {
			return nil, errors.New("excessive player UUIDs")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(uuids) == 0 {
		return nil, errors.New("empty player UUID roster")
	}
	sort.Strings(uuids)
	return uuids, nil
}

func inspectStateRoot(root string) error {
	if !filepath.IsAbs(root) {
		return errors.New("snapshot root must be absolute")
	}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("snapshot root must be a real directory")
	}
	return nil
}

func auditState(source, target string) (StateAudit, error) {
	a := StateAudit{Format: stateAuditFormat}
	if err := inspectStateRoot(source); err != nil {
		return a, err
	}
	if err := inspectStateRoot(target); err != nil {
		return a, err
	}
	srcRoot, err := filepath.EvalSymlinks(source)
	if err != nil {
		return a, err
	}
	tgtRoot, err := filepath.EvalSymlinks(target)
	if err != nil {
		return a, err
	}
	if srcRoot == tgtRoot {
		return a, errors.New("source and target snapshots must be separate")
	}
	for _, pair := range [][2]string{{srcRoot, tgtRoot}, {tgtRoot, srcRoot}} {
		rel, relErr := filepath.Rel(pair[0], pair[1])
		if relErr != nil {
			return a, relErr
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
			return a, errors.New("source and target snapshot directories must not be nested")
		}
	}
	a.SourceUUIDs, err = stateRoster(source)
	if err != nil {
		return a, err
	}
	a.TargetUUIDs, err = stateRoster(target)
	if err != nil {
		return a, err
	}
	sw, err := stateTree(source, "world")
	if err != nil {
		return a, err
	}
	tw, err := stateTree(target, "world")
	if err != nil {
		return a, err
	}
	sp, err := stateTree(source, "plugins")
	if err != nil {
		return a, err
	}
	tp, err := stateTree(target, "plugins")
	if err != nil {
		return a, err
	}
	a.SourceWorldSHA256, a.TargetWorldSHA256 = sw.hash, tw.hash
	a.SourcePluginSHA256, a.TargetPluginSHA256 = sp.hash, tp.hash
	a.WorldFiles, a.PluginFiles = sw.files, sp.files
	for _, excluded := range sw.excluded {
		a.Excluded = append(a.Excluded, "source/"+excluded)
	}
	for _, excluded := range tw.excluded {
		a.Excluded = append(a.Excluded, "target/"+excluded)
	}
	a.Matched = bytes.Equal([]byte(strings.Join(a.SourceUUIDs, "\n")), []byte(strings.Join(a.TargetUUIDs, "\n"))) && sw.hash == tw.hash && sp.hash == tp.hash
	if !a.Matched {
		return a, errors.New("migration data mismatch: UUIDs, world or plugin state differ")
	}
	return a, nil
}

func executeStateAudit(source, target, output string) error {
	if !filepath.IsAbs(output) {
		return errors.New("absolute audit output path required")
	}
	result, err := auditState(source, target)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return writePrivate(output, append(raw, '\n'))
}

// validateStateAuditEvidence не даёт квитанции просто заявить
// равные дайджесты, оставив в свидетельствах посторонний открытый текст.
// Подписанная квитанция должна совпадать с реальным структурированным результатом аудита на диске.
func validateStateAuditEvidence(data []byte, probe Probe) error {
	var a StateAudit
	if err := decodeStrict(data, &a); err != nil {
		return fmt.Errorf("state audit evidence: %w", err)
	}
	if a.Format != stateAuditFormat || !a.Matched || a.WorldFiles < 1 || a.PluginFiles < 0 ||
		!digest(a.SourceWorldSHA256) || !digest(a.SourcePluginSHA256) ||
		a.SourceWorldSHA256 != a.TargetWorldSHA256 || a.SourcePluginSHA256 != a.TargetPluginSHA256 ||
		a.SourceWorldSHA256 != probe.SourceWorldSHA256 || a.TargetWorldSHA256 != probe.TargetWorldSHA256 ||
		a.SourcePluginSHA256 != probe.SourcePluginSHA256 || a.TargetPluginSHA256 != probe.TargetPluginSHA256 ||
		len(a.SourceUUIDs) == 0 || len(a.SourceUUIDs) != len(probe.SourceUUIDs) ||
		len(a.TargetUUIDs) != len(probe.TargetUUIDs) {
		return errors.New("invalid or unbound state audit evidence")
	}
	for _, pair := range [][2][]string{{a.SourceUUIDs, probe.SourceUUIDs}, {a.TargetUUIDs, probe.TargetUUIDs}} {
		left := append([]string(nil), pair[0]...)
		right := append([]string(nil), pair[1]...)
		sort.Strings(left)
		sort.Strings(right)
		for i := range left {
			if !canonicalUUID.MatchString(left[i]) || (i > 0 && left[i] == left[i-1]) || left[i] != right[i] {
				return errors.New("state audit player roster disagrees with receipt")
			}
		}
	}
	return nil
}

// Повторно прочитать исходные замороженные снимки после *всех* проб и снова при живом
// продвижении GA. Поздние тесты не должны незаметно менять ранее одобренное
// состояние игроков, мира или плагинов, сохраняя действующую историческую квитанцию.
func ensureSnapshotStillMatches(p Plan, evidenceDir string) error {
	expectedBytes, err := checkPrivateRegular(filepath.Join(evidenceDir, "uuid-world-plugin-data.evidence"), maxDocument)
	if err != nil {
		return err
	}
	var expected StateAudit
	if err := decodeStrict(expectedBytes, &expected); err != nil {
		return err
	}
	actual, err := auditState(p.SnapshotSourceDir, p.SnapshotTargetDir)
	if err != nil {
		return err
	}
	if !expected.Matched || !actual.Matched || expected.Format != actual.Format ||
		expected.SourceWorldSHA256 != actual.SourceWorldSHA256 || expected.TargetWorldSHA256 != actual.TargetWorldSHA256 ||
		expected.SourcePluginSHA256 != actual.SourcePluginSHA256 || expected.TargetPluginSHA256 != actual.TargetPluginSHA256 ||
		expected.WorldFiles != actual.WorldFiles || expected.PluginFiles != actual.PluginFiles ||
		len(expected.SourceUUIDs) != len(actual.SourceUUIDs) || len(expected.TargetUUIDs) != len(actual.TargetUUIDs) ||
		len(expected.Excluded) != len(actual.Excluded) {
		return errors.New("native snapshot state changed after the signed audit")
	}
	for i := range actual.SourceUUIDs {
		if actual.SourceUUIDs[i] != expected.SourceUUIDs[i] || actual.TargetUUIDs[i] != expected.TargetUUIDs[i] {
			return errors.New("player roster changed after audit")
		}
	}
	for i := range actual.Excluded {
		if actual.Excluded[i] != expected.Excluded[i] {
			return errors.New("snapshot exclusions changed after audit")
		}
	}
	return nil
}
