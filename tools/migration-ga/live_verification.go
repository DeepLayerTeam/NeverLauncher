package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Запечатанный сертификат — историческое свидетельство. Перед окончательной
// приёмкой Migration GA повторно опрашивается действующий Backend, чтобы откат,
// отзыв или изменение инвентаризации не скрывались старой действительной подписью.
func verifyLiveReference(ctx context.Context, b Bundle, p Plan, token string) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("Проверка GA на действующей системе: требуется токен серверной части")
	}
	if err := checkBackendURL(p.Backend); err != nil {
		return err
	}
	if p.ReferenceClass != b.ReferenceClass || p.ProjectID != b.ProjectID || p.RunID != b.RunID || p.CommitSHA != b.CommitSHA || p.SourceVersion != b.SourceVersion || p.TrustedGravitJarSHA256 != b.TrustedGravitJarSHA256 || p.TargetReleaseSHA256 != b.TargetReleaseSHA256 {
		return errors.New("Актуальный план не соответствует подписанному сертификату GA")
	}
	currentSource, err := shaFile(p.SourceArchive, 512<<20)
	if err != nil || currentSource != b.SourceSHA256 {
		return errors.New("Исходный ZIP отсутствует или изменился после сертификации")
	}
	actualVersion, jarHash, err := sourceJarEvidence(p.SourceArchive)
	if err != nil || actualVersion != b.SourceVersion || jarHash != b.TrustedGravitJarSHA256 {
		return errors.New("Зафиксированный Gravit LaunchServer больше недоступен")
	}
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	endpoint := strings.TrimRight(p.Backend, "/") + "/api/v1/admin/migration-runs/" + url.PathEscape(b.RunID) + "/report"
	var report Report
	if err := getJSON(ctx, client, endpoint, token, &report); err != nil {
		return err
	}
	if err := reportVerified(report); err != nil {
		return err
	}
	if report.RunID != b.RunID || report.ProjectID != b.ProjectID || report.SourceSHA256 != b.SourceSHA256 || report.ReportSHA256 != b.ReportSHA256 {
		return errors.New("Выполнение или редакция миграции изменились после сертификации")
	}
	active := false
	for _, ev := range report.Evidence {
		if strings.HasPrefix(ev.Stage, "cutover_scope:") && ev.Details == "active" && ev.State == "verified" && ev.SHA256 == b.TargetReleaseSHA256 {
			active = true
		}
	}
	if !active {
		return errors.New("Сертифицированный целевой релиз больше не активен")
	}
	var review Review
	if err := getJSON(ctx, client, endpoint+"/review", token, &review); err != nil {
		return err
	}
	if review.Status != "rc_reviewed_not_ga_certified" || review.Report.ReportSHA256 != b.ReportSHA256 || review.ReviewedBy != b.ReviewedBy || review.EvidenceSHA256 != b.ReviewEvidenceSHA256 || review.ReviewedAt == "" {
		return errors.New("Заключение оператора больше не соответствует сертифицированным доказательствам")
	}
	if err := reportVerified(review.Report); err != nil {
		return err
	}
	return nil
}

// Вызывается только после проверки подписей и всех сохранённых свидетельств.
// Каждый эталон имеет собственный доверенный план и повторно проверяется при приёмке.
func verifyCohortLive(ctx context.Context, inputs map[string]CohortInput, plans map[string]string, token string) error {
	for _, class := range referenceClasses {
		file := plans[class]
		if file == "" {
			return fmt.Errorf("Отсутствует актуальный план для %s", class)
		}
		raw, err := checkPrivateRegular(file, maxDocument)
		if err != nil {
			return err
		}
		var p Plan
		if err := decodeStrict(raw, &p); err != nil {
			return err
		}
		// Закрытый ключ подписи не нужен для проверки ссылки: после сертификации его могли
		// заменить или удалить. Вместо него проверяйте поля привязки источника, коммита и Backend.
		if p.ReferenceClass != class || !commitHash(p.CommitSHA) || !digest(p.TrustedGravitJarSHA256) || !digest(p.TargetReleaseSHA256) {
			return errors.New("Некорректное значение: действующий эталонный план")
		}
		b, err := readCertificate(inputs[class].Certificate)
		if err != nil {
			return err
		}
		if err := ensureSnapshotStillMatches(p, inputs[class].EvidenceDir); err != nil {
			return fmt.Errorf("снимок состояния %s: %w", class, err)
		}
		if err := verifyLiveReference(ctx, b, p, token); err != nil {
			return fmt.Errorf("%s: %w", class, err)
		}
	}
	return nil
}

func loadCohortPlanPaths(single, modded, network string) map[string]string {
	return map[string]string{"fileauth-single": single, "sql-modded": modded, "proxy-network": network}
}

// Исключите случайный запуск офлайн-проверки как приёмки GA. Автоматизация
// оператора использует отдельную команду и должна передать три действующих плана.
func verifyCohortLiveCommand(ctx context.Context, key string, cohort map[string]CohortInput, planFiles map[string]string) error {
	if err := verifyCohort(key, cohort); err != nil {
		return err
	}
	return verifyCohortLive(ctx, cohort, planFiles, os.Getenv("LAUNCHER_MIGRATION_GA_TOKEN"))
}
