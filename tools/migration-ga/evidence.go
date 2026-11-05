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

// Свидетельства не заменяют настоящие проверки Minecraft и БД. Это
// точный сохранённый результат таких проверок, который можно независимо проверить даже после
// завершения процесса сертификации.
func verifyExecutable(c Check) error {
	info, err := os.Lstat(c.Command[0])
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Size() <= 0 || info.Size() > 128<<20 {
		return errors.New("GA check must be an executable, bounded, regular file (no symlink)")
	}
	actual, err := shaFile(c.Command[0], 128<<20)
	if err != nil {
		return err
	}
	if actual != c.ExecutableSHA256 {
		return errors.New("GA check executable SHA-256 differs from approved plan")
	}
	return nil
}

func preserveEvidence(dir, name, source, expected string, receipt []byte) error {
	if !referenceCheck(name) {
		return errors.New("unknown GA check")
	}
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 128<<20 {
		return errors.New("GA evidence is not a bounded regular file")
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
		return errors.New("evidence mutated during copy")
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
		return nil, errors.New("evidence must be a bounded regular file, not a symlink")
	}
	return os.ReadFile(filename)
}

func verifyEvidence(b Bundle, dir string) error {
	if !filepath.IsAbs(dir) || dir == "" {
		return errors.New("absolute evidence directory required")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("evidence directory must be private (0700)")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) != len(requiredForClass(b.ReferenceClass))*2 {
		return errors.New("incomplete or unexpected evidence files")
	}
	approved := make(map[string]bool, len(requiredForClass(b.ReferenceClass))*2)
	for _, name := range requiredForClass(b.ReferenceClass) {
		approved[name+".receipt.json"] = true
		approved[name+".evidence"] = true
	}
	for _, entry := range entries {
		if !approved[entry.Name()] || !entry.Type().IsRegular() {
			return fmt.Errorf("unexpected or nonregular evidence: %s", entry.Name())
		}
	}
	for _, check := range b.Checks {
		raw, err := checkPrivateRegular(filepath.Join(dir, check.Name+".receipt.json"), 4<<20)
		if err != nil {
			return fmt.Errorf("%s receipt: %w", check.Name, err)
		}
		var probe Probe
		if err = decodeStrict(raw, &probe); err != nil {
			return err
		}
		// Сертификат подписывает каноническую нормализованную квитанцию, а не завершающие
		// пробелы или форматирование под контролем оператора.
		canonical, err := json.Marshal(probe)
		if err != nil {
			return err
		}
		if hash(canonical) != check.SHA256 || !probe.Passed || probe.Name != check.Name || probe.RunID != b.RunID || probe.ReportSHA256 != b.ReportSHA256 || probe.SourceSHA256 != b.SourceSHA256 || probe.SourceVersion != b.SourceVersion || probe.TargetReleaseSHA256 != b.TargetReleaseSHA256 || probe.EvidenceSHA256 != check.EvidenceSHA256 {
			return fmt.Errorf("%s receipt not bound to certificate", check.Name)
		}
		evidence := filepath.Join(dir, check.Name+".evidence")
		info, err := os.Lstat(evidence)
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 128<<20 {
			return fmt.Errorf("%s evidence absent or nonregular", check.Name)
		}
		sum, err := shaFile(evidence, 128<<20)
		if err != nil || sum != check.EvidenceSHA256 {
			return fmt.Errorf("Несоответствие: %s свидетельство SHA-256", check.Name)
		}
		if check.Name == "uuid-world-plugin-data" {
			auditRaw, readErr := os.ReadFile(evidence)
			if readErr != nil || len(auditRaw) > maxDocument || validateStateAuditEvidence(auditRaw, probe) != nil {
				return errors.New("retained state audit does not match signed receipt")
			}
			if len(probe.SourceUUIDs) == 0 || len(probe.SourceUUIDs) != len(probe.TargetUUIDs) || !digest(probe.SourceWorldSHA256) || probe.SourceWorldSHA256 != probe.TargetWorldSHA256 || !digest(probe.SourcePluginSHA256) || probe.SourcePluginSHA256 != probe.TargetPluginSHA256 {
				return errors.New("incomplete world/identity cross-check")
			}
			source := append([]string(nil), probe.SourceUUIDs...)
			target := append([]string(nil), probe.TargetUUIDs...)
			sort.Strings(source)
			sort.Strings(target)
			if !bytes.Equal([]byte(strings.Join(source, "\n")), []byte(strings.Join(target, "\n"))) {
				return errors.New("Несоответствие: source/target UUID")
			}
			for i, id := range source {
				if id == "" || (i > 0 && id == source[i-1]) {
					return errors.New("duplicate or empty player UUID")
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
		return nil, errors.New("expected a single PEM public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("Требуемый формат для доверенный ключ: Ed25519")
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

// Один оператор не может объявить всю инфраструктуру мигрированной, проверив только
// самый простой сервер. Для каждой обязательной ссылки нужна собственная подписанная квитанция и все
// 13 реальных проверок; проекты и исходные архивы должны действительно различаться.
func verifyCohort(keyFile string, cohort map[string]CohortInput) error {
	public, err := loadTrustedKey(keyFile)
	if err != nil {
		return err
	}
	if len(cohort) != len(referenceClasses) {
		return errors.New("all three migration reference classes required")
	}
	seenProject, seenSource, seenRun := map[string]bool{}, map[string]bool{}, map[string]bool{}
	commit := ""
	for _, class := range referenceClasses {
		input, ok := cohort[class]
		if !ok || input.Certificate == "" || input.EvidenceDir == "" {
			return fmt.Errorf("missing reference class %s", class)
		}
		b, err := readCertificate(input.Certificate)
		if err != nil {
			return err
		}
		if err = verifyBundle(b, public); err != nil {
			return fmt.Errorf("%s: %w", class, err)
		}
		if b.ReferenceClass != class {
			return fmt.Errorf("%s: incorrect certified reference class", class)
		}
		if err = verifyEvidence(b, input.EvidenceDir); err != nil {
			return fmt.Errorf("%s: %w", class, err)
		}
		if seenProject[b.ProjectID] || seenSource[b.SourceSHA256] || seenRun[b.RunID] {
			return errors.New("cohort reused a project, archive or migration run")
		}
		seenProject[b.ProjectID], seenSource[b.SourceSHA256], seenRun[b.RunID] = true, true, true
		if commit == "" {
			commit = b.CommitSHA
		} else if commit != b.CommitSHA {
			return errors.New("cohort mixes source commits")
		}
	}
	return nil
}
