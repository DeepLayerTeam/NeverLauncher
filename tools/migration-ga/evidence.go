package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Свидетельства не заменяют реальные проверки Minecraft и БД. Это их точный
// долговременно сохранённый результат, который можно независимо перепроверить
// после завершения процесса сертификации.
func verifyExecutable(c Check) error {
	info, err := os.Lstat(c.Command[0])
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Size() <= 0 || info.Size() > 128<<20 {
		return errors.New("Для проверки GA требуется обычный исполняемый файл ограниченного размера без символических ссылок")
	}
	actual, err := shaFile(c.Command[0], 128<<20)
	if err != nil {
		return err
	}
	if actual != c.ExecutableSHA256 {
		return errors.New("SHA-256 исполняемого файла проверки GA отличается от утверждённого плана")
	}
	return nil
}

func preserveEvidence(dir, name, source, expected string, receipt []byte) error {
	if !referenceCheck(name) {
		return errors.New("Неизвестное значение: проверка GA")
	}
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 128<<20 {
		return errors.New("Файл доказательств GA не является обычным файлом допустимого размера")
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	temp, err := os.CreateTemp(dir, ".ga-evidence-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err = temp.Chmod(0600); err != nil {
		temp.Close()
		return err
	}
	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(temp, hasher), io.LimitReader(input, (128<<20)+1))
	if err != nil {
		temp.Close()
		return err
	}
	if written != info.Size() || hex.EncodeToString(hasher.Sum(nil)) != expected {
		temp.Close()
		return errors.New("Доказательства изменились во время копирования")
	}
	if err = temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	target := filepath.Join(dir, name+".evidence")
	if err = os.Link(temp.Name(), target); err != nil {
		return err
	}
	if err = writePrivate(filepath.Join(dir, name+".receipt.json"), append(receipt, '\n')); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func referenceCheck(s string) bool {
	for _, requiredName := range required {
		if s == requiredName {
			return true
		}
	}
	return false
}

func checkPrivateRegular(filename string, limit int64) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("Подтверждающие данные должны храниться в обычном файле допустимого размера, не в символической ссылке")
	}
	return os.ReadFile(filename)
}

func verifyEvidence(b Bundle, dir string) error {
	if !filepath.IsAbs(dir) || dir == "" {
		return errors.New("Требуется абсолютный путь к каталогу подтверждающих данных")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("Каталог подтверждающих данных: требуется приватные права 0700")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) != len(requiredForClass(b.ReferenceClass))*2 {
		return errors.New("Неполный или неожиданный набор файлов с доказательными данными")
	}
	approved := make(map[string]bool, len(requiredForClass(b.ReferenceClass))*2)
	for _, name := range requiredForClass(b.ReferenceClass) {
		approved[name+".receipt.json"] = true
		approved[name+".evidence"] = true
	}
	for _, entry := range entries {
		if !approved[entry.Name()] || !entry.Type().IsRegular() {
			return fmt.Errorf("Неожиданные подтверждающие данные или файл неподдерживаемого типа: %s", entry.Name())
		}
	}
	for _, check := range b.Checks {
		raw, err := checkPrivateRegular(filepath.Join(dir, check.Name+".receipt.json"), 4<<20)
		if err != nil {
			return fmt.Errorf("квитанция проверки %s: %w", check.Name, err)
		}
		var probe Probe
		if err = decodeStrict(raw, &probe); err != nil {
			return err
		}
		// Сертификат подписывает каноническую нормализованную квитанцию, а не завершающие
		// пробелы или форматирование, управляемое оператором.
		canonical, err := json.Marshal(probe)
		if err != nil {
			return err
		}
		if hash(canonical) != check.SHA256 || !probe.Passed || probe.Name != check.Name || probe.RunID != b.RunID || probe.ReportSHA256 != b.ReportSHA256 || probe.SourceSHA256 != b.SourceSHA256 || probe.SourceVersion != b.SourceVersion || probe.TargetReleaseSHA256 != b.TargetReleaseSHA256 || probe.EvidenceSHA256 != check.EvidenceSHA256 {
			return fmt.Errorf("Квитанция %s не привязана к сертификату", check.Name)
		}
		evidence := filepath.Join(dir, check.Name+".evidence")
		info, err := os.Lstat(evidence)
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 128<<20 {
			return fmt.Errorf("Доказательства %s отсутствуют или представлены не обычным файлом", check.Name)
		}
		sum, err := shaFile(evidence, 128<<20)
		if err != nil || sum != check.EvidenceSHA256 {
			return fmt.Errorf("Несовпадение SHA-256 подтверждающих данных %s", check.Name)
		}
		if check.Name == "uuid-world-plugin-data" {
			auditRaw, readErr := os.ReadFile(evidence)
			if readErr != nil || len(auditRaw) > maxDocument || validateStateAuditEvidence(auditRaw, probe) != nil {
				return errors.New("сохранённый аудит состояния не совпадает с подписанное подтверждение")
			}
			if len(probe.SourceUUIDs) == 0 || len(probe.SourceUUIDs) != len(probe.TargetUUIDs) || !digest(probe.SourceWorldSHA256) || probe.SourceWorldSHA256 != probe.TargetWorldSHA256 || !digest(probe.SourcePluginSHA256) || probe.SourcePluginSHA256 != probe.TargetPluginSHA256 {
				return errors.New("Сверка миров и учётных записей выполнена не полностью")
			}
			source := append([]string(nil), probe.SourceUUIDs...)
			target := append([]string(nil), probe.TargetUUIDs...)
			sort.Strings(source)
			sort.Strings(target)
			if !bytes.Equal([]byte(strings.Join(source, "\n")), []byte(strings.Join(target, "\n"))) {
				return errors.New("Несовпадение: UUID источника и цели")
			}
			for i, id := range source {
				if id == "" || (i > 0 && id == source[i-1]) {
					return errors.New("UUID игрока повторяется или отсутствует")
				}
			}
		}
	}
	return nil
}

type CohortInput struct {
	Certificate string
	EvidenceDir string
}

func loadTrustedKey(filename string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, trailing := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(trailing)) > 0 {
		return nil, errors.New("Ожидался один открытый ключ в формате PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("Доверенный ключ: требуется Ed25519")
	}
	return pub, nil
}

func readCertificate(filename string) (Bundle, error) {
	data, err := checkPrivateRegular(filename, maxDocument)
	if err != nil {
		return Bundle{}, err
	}
	var cert Bundle
	err = decodeStrict(data, &cert)
	return cert, err
}

// Нельзя объявлять миграцию всех серверов завершённой после проверки только
// самого простого сервера. Каждому эталону необходимы отдельная подписанная
// квитанция и все 13 реальных проверок; проекты и архивы должны различаться.
func verifyCohort(keyFile string, cohort map[string]CohortInput) error {
	public, err := loadTrustedKey(keyFile)
	if err != nil {
		return err
	}
	if len(cohort) != len(referenceClasses) {
		return errors.New("Требуются все три категории эталонных данных миграции")
	}
	seenProject, seenSource, seenRun := map[string]bool{}, map[string]bool{}, map[string]bool{}
	commit := ""
	for _, class := range referenceClasses {
		input, ok := cohort[class]
		if !ok || input.Certificate == "" || input.EvidenceDir == "" {
			return fmt.Errorf("Отсутствует: класс ссылок %s", class)
		}
		b, err := readCertificate(input.Certificate)
		if err != nil {
			return err
		}
		if err = verifyBundle(b, public); err != nil {
			return fmt.Errorf("%s: %w", class, err)
		}
		if b.ReferenceClass != class {
			return fmt.Errorf("%s: неверный сертифицированный эталонный класс", class)
		}
		if err = verifyEvidence(b, input.EvidenceDir); err != nil {
			return fmt.Errorf("%s: %w", class, err)
		}
		if seenProject[b.ProjectID] || seenSource[b.SourceSHA256] || seenRun[b.RunID] {
			return errors.New("В наборе эталонных проверок повторно использован проект, архив или запуск миграции")
		}
		seenProject[b.ProjectID], seenSource[b.SourceSHA256], seenRun[b.RunID] = true, true, true
		if commit == "" {
			commit = b.CommitSHA
		} else if commit != b.CommitSHA {
			return errors.New("В наборе эталонных проверок смешаны разные исходные коммиты")
		}
	}
	return nil
}
