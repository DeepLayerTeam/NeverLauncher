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

// A sealed certificate is historical evidence. This check queries the live
// backend again before final Migration GA promotion, so a rollback, revocation
// or revised inventory cannot be hidden by a valid historical signature.
func verifyLiveReference(ctx context.Context, b Bundle, p Plan, token string) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("Проверка GA на действующей системе: требуется токен серверной части")
	}
	if err := checkBackendURL(p.Backend); err != nil {
		return err
	}
	if p.ReferenceClass != b.ReferenceClass || p.ProjectID != b.ProjectID || p.RunID != b.RunID || p.CommitSHA != b.CommitSHA || p.SourceVersion != b.SourceVersion || p.TrustedGravitJarSHA256 != b.TrustedGravitJarSHA256 || p.TargetReleaseSHA256 != b.TargetReleaseSHA256 {
		return errors.New("live plan differs from signed GA certificate")
	}
	currentSource, err := shaFile(p.SourceArchive, 512<<20)
	if err != nil || currentSource != b.SourceSHA256 {
		return errors.New("source ZIP missing or changed since certification")
	}
	actualVersion, jarHash, err := sourceJarEvidence(p.SourceArchive)
	if err != nil || actualVersion != b.SourceVersion || jarHash != b.TrustedGravitJarSHA256 {
		return errors.New("pinned Gravit LaunchServer is no longer present")
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
		return errors.New("migration run/revision changed after certification")
	}
	active := false
	for _, ev := range report.Evidence {
		if strings.HasPrefix(ev.Stage, "cutover_scope:") && ev.Details == "active" && ev.State == "verified" && ev.SHA256 == b.TargetReleaseSHA256 {
			active = true
		}
	}
	if !active {
		return errors.New("certified target release is no longer active")
	}
	var review Review
	if err := getJSON(ctx, client, endpoint+"/review", token, &review); err != nil {
		return err
	}
	if review.Status != "rc_reviewed_not_ga_certified" || review.Report.ReportSHA256 != b.ReportSHA256 || review.ReviewedBy != b.ReviewedBy || review.EvidenceSHA256 != b.ReviewEvidenceSHA256 || review.ReviewedAt == "" {
		return errors.New("operator review no longer matches certified evidence")
	}
	if err := reportVerified(review.Report); err != nil {
		return err
	}
	return nil
}

// Called only after verifying the signatures and all retained evidence. Every
// reference has a separate trusted plan and is rechecked at promotion time.
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
		// The private signing key is not needed to verify a reference; it may
		// have been rotated/removed since certification. Validate the fields
		// that bind the source, commit and backend instead.
		if p.ReferenceClass != class || !commitHash(p.CommitSHA) || !digest(p.TrustedGravitJarSHA256) || !digest(p.TargetReleaseSHA256) {
			return errors.New("Некорректное значение: действующий эталонный план")
		}
		b, err := readCertificate(inputs[class].Certificate)
		if err != nil {
			return err
		}
		if err := ensureSnapshotStillMatches(p, inputs[class].EvidenceDir); err != nil {
			return fmt.Errorf("%s snapshot: %w", class, err)
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

// Guard accidental execution of an offline verify as a GA promotion. Operator
// automation uses this distinct command and must provide three live plans.
func verifyCohortLiveCommand(ctx context.Context, key string, cohort map[string]CohortInput, planFiles map[string]string) error {
	if err := verifyCohort(key, cohort); err != nil {
		return err
	}
	return verifyCohortLive(ctx, cohort, planFiles, os.Getenv("LAUNCHER_MIGRATION_GA_TOKEN"))
}
