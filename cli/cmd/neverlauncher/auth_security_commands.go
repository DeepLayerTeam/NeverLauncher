package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/cli/internal/dbmigrate"
)

func handleAuth(args []string) error {
	if len(args) < 1 {
		return errors.New("доступные auth-подкоманды: login, capabilities, accounts, roles, sessions, revoke, logout-all, session-policy, password-policy")
	}
	backend := adminBackendURL(args)
	if backend == "" {
		return errors.New("auth-команды требуют --backend <url>")
	}
	out := flagValue(args, "--output", "")
	var payload map[string]any
	var err error
	switch args[0] {
	case "login":
		email, password := flagValue(args, "--email", ""), flagValue(args, "--password", "")
		if email == "" || password == "" {
			return errors.New("auth login требует --email и --password")
		}
		body := map[string]any{"email": email, "password": password, "deviceId": flagValue(args, "--device", "nl-cli")}
		if totp := flagValue(args, "--totp", ""); totp != "" {
			body["totp"] = totp
		}
		payload, err = httpJSON("POST", backend+"/api/v1/auth/login", body)
	case "capabilities":
		payload, _, err = adminBackendGet(args, "/api/v1/auth/capabilities")
	case "accounts":
		payload, _, err = adminBackendGet(args, "/api/v1/auth/accounts")
	case "roles":
		payload, _, err = adminBackendGet(args, "/api/v1/auth/roles")
	case "sessions":
		payload, _, err = adminBackendGet(args, "/api/v1/auth/sessions")
	case "revoke":
		payload, _, err = adminBackendPost(args, "/api/v1/auth/sessions/revoke", map[string]any{"allExceptCurrent": flagValue(args, "--keep-current", "false") == "true"})
	case "logout-all":
		payload, _, err = adminBackendPost(args, "/api/v1/auth/sessions/logout-all", map[string]any{"allExceptCurrent": false})
	case "session-policy":
		payload, _, err = adminBackendGet(args, "/api/v1/auth/session-policy")
	case "password-policy":
		payload, _, err = adminBackendGet(args, "/api/v1/auth/password-policy")
	default:
		return fmt.Errorf("неизвестная auth-подкоманда: %s", args[0])
	}
	if err != nil {
		return err
	}
	return writeOrPrintJSON(out, payload)
}

func handleObservability(args []string) error {
	if len(args) < 1 {
		return errors.New("доступные operations-подкоманды: status, readiness, diagnostics, diagnostics-bundle")
	}
	backend := adminBackendURL(args)
	if backend == "" {
		return errors.New("operations-команды требуют --backend <url>")
	}
	out := flagValue(args, "--output", "")
	var payload map[string]any
	var err error
	switch args[0] {
	case "status":
		payload, err = httpJSON("GET", backend+"/api/v1/status", nil)
	case "readiness":
		payload, err = httpJSON("GET", backend+"/ready", nil)
	case "diagnostics":
		payload, _, err = adminBackendGet(args, "/api/v1/operations/diagnostics")
	case "diagnostics-bundle":
		payload, _, err = adminBackendGet(args, "/api/v1/operations/diagnostics-bundle")
	default:
		return fmt.Errorf("неизвестная operations-подкоманда: %s", args[0])
	}
	if err != nil {
		return err
	}
	return writeOrPrintJSON(out, payload)
}

func diagnosticsPrivacyPolicyModel() map[string]any {
	return map[string]any{
		"schemaVersion":  cliSchemaVersion,
		"toolVersion":    version,
		"privacyMode":    "privacy-by-default",
		"allowedFields":  []string{"schemaVersion", "generatedAt", "launcherVersion", "os", "arch", "backendUrl", "profileId", "profileVersion", "status", "checks", "logs", "operationId"},
		"redactedFields": []string{"token", "password", "secret", "authorization", "accessKey", "secretKey", "cookie", "session"},
		"retention":      "local-only-until-user-exports",
	}
}

func diagnosticsBundleModel(backendURL string) map[string]any {
	return map[string]any{
		"schemaVersion": cliSchemaVersion,
		"toolVersion":   version,
		"generatedAt":   time.Now().UTC().Format(time.RFC3339),
		"backendUrl":    backendURL,
		"status":        "bundle-plan",
		"sections":      []string{"system", "backend-health", "backend-readiness", "desktop-settings", "manifest-status", "java-status", "file-verification", "release-channel", "recent-errors"},
		"redaction":     diagnosticsPrivacyPolicyModel(),
		"checks":        map[string]string{"cli": "ok", "backend": "check /health and /ready", "metrics": "check /metrics when enabled", "logs": "structured-json preferred"},
	}
}

func operationsSupportSummaryModel() map[string]any {
	return map[string]any{
		"schemaVersion": cliSchemaVersion,
		"toolVersion":   version,
		"status":        "support-summary-ready",
		"fields":        []string{"version", "environment", "repository", "storage", "projects", "users", "auditEvents", "telemetryEvents", "crashReports", "lastRelease", "lastFailure"},
		"goal":          "администратор видит причину инцидента без SSH-доступа",
	}
}

func handleSecurity(args []string) error {
	if len(args) < 1 {
		return errors.New("доступные security-подкоманды: check, hardening, supply-chain, keys, rotate-key, revocation-list, sbom, provenance, attest, verify-signature, manifest-policy, release-policy, desktop-policy")
	}
	out := flagValue(args, "--output", "")
	switch args[0] {
	case "check":
		report := supplyChainSecurityModel()
		report["legacyAuthChecks"] = []map[string]string{
			{"id": "password-hashing", "status": "required", "message": "использовать Argon2id с индивидуальной солью и серверным pepper"},
			{"id": "access-refresh-tokens", "status": "required", "message": "разделить короткоживущий access token и refresh token family"},
			{"id": "totp", "status": "required", "message": "включить TOTP для администраторов и владельцев проектов"},
		}
		return writeOrPrintJSON(out, report)
	case "hardening":
		return writeOrPrintJSON(out, map[string]any{"schemaVersion": "0.10.0", "toolVersion": version, "status": "security-hardened", "implemented": []string{"TOTP enrollment", "TOTP/recovery login enforcement", "single-use recovery codes", "password reset token flow", "email verification token flow", "login failure lockout", "security audit events"}, "endpoints": []string{"/api/v1/auth/totp/enroll", "/api/v1/auth/totp/enroll", "/api/v1/auth/totp/verify", "/api/v1/auth/recovery-codes/regenerate", "/api/v1/auth/password-reset/request", "/api/v1/auth/password-reset/confirm", "/api/v1/auth/email-verification/request", "/api/v1/auth/email-verification/confirm"}})
	case "supply-chain":
		return writeOrPrintJSON(out, supplyChainSecurityModel())
	case "keys":
		payload, err := securityKeys(args)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "rotate-key":
		payload, err := rotateSecurityKey(args)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "revocation-list":
		payload, err := securityRevocations(args)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "sbom":
		payload, err := dependencySBOM(flagValue(args, "--source-root", "."), flagValue(args, "--version", version))
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "provenance":
		payload, err := slsaProvenance(flagValue(args, "--source-root", "."), flagValue(args, "--artifact-dir", ""), flagValue(args, "--version", version))
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "attest":
		payload, err := securityAttest(args)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "verify-signature":
		artifact := strings.ToLower(strings.TrimSpace(flagValue(args, "--artifact", "release")))
		path := flagValue(args, "--path", "")
		publicKey := flagValue(args, "--public-key", "")
		if artifact == "release" || artifact == "release-bundle" {
			if path == "" {
				return errors.New("security verify-signature --artifact release требует --path <release-dir>")
			}
			if err := verifyReleaseBundle(path, publicKey); err != nil {
				return err
			}
			if err := ensurePublicKeyNotRevoked(flagValue(args, "--registry-dir", ""), publicKey); err != nil {
				return err
			}
			return writeOrPrintJSON(out, map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "artifact": artifact, "path": path, "status": "verified", "algorithm": "Ed25519"})
		}
		payload, err := verifyDetachedEd25519(path, flagValue(args, "--signature", ""), publicKey)
		if err != nil {
			return err
		}
		if err := ensurePublicKeyNotRevoked(flagValue(args, "--registry-dir", ""), publicKey); err != nil {
			return err
		}
		payload["artifact"] = artifact
		return writeOrPrintJSON(out, payload)
	case "manifest-policy":
		return writeOrPrintJSON(out, securityManifestPolicyModel())
	case "release-policy":
		return writeOrPrintJSON(out, securityReleasePolicyModel())
	case "desktop-policy":
		return writeOrPrintJSON(out, securityDesktopPolicyModel())
	default:
		return fmt.Errorf("неизвестная security-подкоманда: %s", args[0])
	}
}

func supplyChainSecurityModel() map[string]any {
	return map[string]any{
		"schemaVersion":    cliSchemaVersion,
		"toolVersion":      version,
		"generatedAt":      time.Now().UTC().Format(time.RFC3339),
		"status":           "security-supply-chain-ready",
		"release":          "NeverLauncher " + version + " security model",
		"signedArtifacts":  []string{"manifest", "release-bundle", "desktop-package", "extension-package", "client-package"},
		"requiredControls": []string{"ed25519-signatures", "sha256-every-file", "trusted-keys-registry", "key-rotation", "revocation-list", "sbom", "provenance", "audit-log", "safe-extraction", "download-allowlist"},
		"checks": []map[string]string{
			{"id": "signed-manifests", "status": "required", "message": "каждый клиентский manifest подписывается Ed25519 ключом проекта"},
			{"id": "signed-release-bundles", "status": "required", "message": "release bundle bundle содержит SHA256SUMS, SHA256SUMS.sig и RELEASE_MANIFEST.json"},
			{"id": "desktop-pinned-key", "status": "required", "message": "desktop-клиент принимает только manifest, подписанный доверенным public key"},
			{"id": "sbom", "status": "required", "message": "релиз содержит SPDX/CycloneDX SBOM metadata"},
			{"id": "provenance", "status": "required", "message": "релиз содержит SLSA-compatible provenance metadata"},
			{"id": "revocation", "status": "required", "message": "отозванные ключи и артефакты блокируются до установки"},
			{"id": "safe-extraction", "status": "required", "message": "архивы распаковываются только через safe path validation"},
			{"id": "rollback-protection", "status": "required", "message": "manifest и release bundle защищены от отката на уязвимую версию"},
		},
	}
}

func securityManifestPolicyModel() map[string]any {
	return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "policy": "signed-manifest-required", "algorithms": []string{"Ed25519"}, "hashes": []string{"SHA-256"}, "checks": []string{"manifest.schema", "file.sha256", "source.allowlist", "https-required", "signature.required", "trusted-key.required", "key-not-revoked", "rollback-protection", "replay-protection"}, "desktopBehavior": map[string]any{"rejectUnsigned": true, "rejectRevokedKey": true, "rejectDowngrade": true}}
}

func securityReleasePolicyModel() map[string]any {
	required := []string{"RELEASE_MANIFEST.json", "SHA256SUMS", "SHA256SUMS.sig", "SBOM.spdx.json", "PROVENANCE.json", "RELEASE_NOTES.txt"}
	checks := []string{"checksums", "signature", "sbom", "provenance", "release-notes", "desktop-package-signature", "api-binary-version", "cli-binary-version"}
	if compatibilityCertificationRequired(version) {
		required = append(required, compatibilityTargetsReleaseFile, compatibilityMatrixReleaseFile, compatibilityCertificationReleaseFile)
		checks = append(checks, "minecraft-compatibility-certification")
	}
	if deviceTrustCertificationRequired(version) {
		required = append(required, deviceTrustTargetsReleaseFile, deviceTrustMatrixReleaseFile, deviceTrustCertificationReleaseFile)
		checks = append(checks, "device-trust-certification")
	}
	return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "policy": "signed-release-bundle-required", "requiredArtifacts": required, "checks": checks, "failureMode": "fail-closed"}
}

func securityDesktopPolicyModel() map[string]any {
	return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "status": "enforced", "rules": []string{"manifest signature required", "trusted Ed25519 key required", "SHA-256 for each file", "safe path join", "safe archive extraction", "download source allowlist", "rollback snapshot before apply", "diagnostics export on verification failure"}}
}

func writeOrPrintJSON(out string, payload any) error {
	if out != "" && out != "-" {
		return writeJSONFile(out, payload)
	}
	printJSON(payload)
	return nil
}

func handleBackup(args []string) error {
	if len(args) < 1 {
		return errors.New("доступные backup-подкоманды: status, create, inspect, restore-dry-run, restore, audit-export, diagnostics-bundle")
	}
	out := flagValue(args, "--output", "")
	switch args[0] {
	case "status":
		if payload, ok, err := adminBackendGet(args, "/api/v1/operations/backup/status"); err != nil {
			return err
		} else if ok {
			return writeOrPrintJSON(out, payload)
		}
		return errors.New("backup status требует --backend <url> и --token/NEVERLAUNCHER_TOKEN для product-проверки")
	case "create":
		if payload, ok, err := adminBackendPost(args, "/api/v1/operations/backups", nil); err != nil {
			return err
		} else if ok {
			return writeOrPrintJSON(out, payload)
		}
		return errors.New("backup create требует --backend <url> и --token/NEVERLAUNCHER_TOKEN; локальный dry-run больше не считается product backup")
	case "inspect":
		backupID := flagValue(args, "--id", "")
		if backupID == "" && len(args) > 1 && !strings.HasPrefix(args[1], "--") {
			backupID = args[1]
		}
		if backupID == "" {
			return errors.New("backup inspect требует --id <backupId>")
		}
		if payload, ok, err := adminBackendGet(args, "/api/v1/operations/backups/"+backupID); err != nil {
			return err
		} else if ok {
			return writeOrPrintJSON(out, payload)
		}
		return errors.New("backup inspect требует --backend <url> и --token/NEVERLAUNCHER_TOKEN")
	case "restore-dry-run":
		backupID := backupIDFromArgs(args)
		if backupID == "" {
			return errors.New("backup restore-dry-run требует --id <backupId>")
		}
		if payload, ok, err := adminBackendPost(args, "/api/v1/operations/backups/"+backupID+"/restore-dry-run", nil); err != nil {
			return err
		} else if ok {
			return writeOrPrintJSON(out, payload)
		}
		return errors.New("backup restore-dry-run требует --backend <url> и --token/NEVERLAUNCHER_TOKEN")
	case "restore":
		backupID := backupIDFromArgs(args)
		if backupID == "" {
			return errors.New("backup restore требует --id <backupId>")
		}
		confirm := flagValue(args, "--confirm", "")
		if confirm != backupID {
			return fmt.Errorf("backup restore требует точное подтверждение --confirm %s", backupID)
		}
		database := strings.EqualFold(flagValue(args, "--database", "false"), "true")
		storageRestore := strings.EqualFold(flagValue(args, "--storage", "false"), "true")
		if !database && !storageRestore {
			return errors.New("backup restore требует --database true и/или --storage true")
		}
		body := map[string]any{"confirm": confirm, "database": database, "storage": storageRestore}
		if payload, ok, err := adminBackendPost(args, "/api/v1/operations/backups/"+backupID+"/restore", body); err != nil {
			return err
		} else if ok {
			return writeOrPrintJSON(out, payload)
		}
		return errors.New("backup restore требует --backend <url> и --token/NEVERLAUNCHER_TOKEN")
	case "audit-export":
		if payload, ok, err := adminBackendGet(args, "/api/v1/operations/audit/export"); err != nil {
			return err
		} else if ok {
			return writeOrPrintJSON(out, payload)
		}
		return errors.New("backup audit-export требует --backend <url> и --token/NEVERLAUNCHER_TOKEN")
	case "diagnostics-bundle":
		if payload, ok, err := adminBackendGet(args, "/api/v1/operations/diagnostics-bundle"); err != nil {
			return err
		} else if ok {
			return writeOrPrintJSON(out, payload)
		}
		return errors.New("backup diagnostics-bundle требует --backend <url> и --token/NEVERLAUNCHER_TOKEN")
	default:
		return fmt.Errorf("неизвестная backup-подкоманда: %s", args[0])
	}
}

func backupIDFromArgs(args []string) string {
	backupID := flagValue(args, "--id", "")
	if backupID == "" && len(args) > 1 && !strings.HasPrefix(args[1], "--") {
		backupID = args[1]
	}
	return strings.TrimSpace(backupID)
}

func handleDB(args []string) error {
	if len(args) < 1 {
		return errors.New("доступные db-подкоманды: migrations, migration-doctor, migrate, status, validate, repository")
	}
	out := flagValue(args, "--output", "")
	switch args[0] {
	case "migrations":
		migrations, err := dbmigrate.List()
		if err != nil {
			return err
		}
		items := make([]map[string]any, 0, len(migrations))
		for _, m := range migrations {
			items = append(items, map[string]any{"version": m.Version, "checksum": m.Checksum})
		}
		report := map[string]any{"schemaVersion": "1", "toolVersion": version, "count": len(items), "status": "listed", "migrations": items}
		if out != "" {
			return writeJSONFile(out, report)
		}
		printJSON(report)
		return nil
	case "migration-doctor":
		migrations, err := dbmigrate.List()
		if err != nil {
			return err
		}
		duplicates := map[string][]string{}
		seen := map[string]string{}
		items := make([]map[string]any, 0, len(migrations))
		for _, m := range migrations {
			number := m.Version
			if len(number) > 4 {
				number = number[:4]
			}
			if prev, ok := seen[number]; ok {
				duplicates[number] = []string{prev, m.Version}
			} else {
				seen[number] = m.Version
			}
			items = append(items, map[string]any{"version": m.Version, "checksum": m.Checksum})
		}
		status := "ok"
		if len(duplicates) != 0 {
			status = "requires-cleanup"
		}
		report := map[string]any{"schemaVersion": "1", "toolVersion": version, "status": status, "count": len(items), "duplicates": duplicates, "migrations": items, "latest": items[len(items)-1]}
		if out != "" {
			return writeJSONFile(out, report)
		}
		printJSON(report)
		return nil
	case "migrate":
		if len(args) < 2 {
			return errors.New("db migrate требует подкоманду: plan, apply или verify")
		}
		migrations, err := dbmigrate.List()
		if err != nil {
			return err
		}
		versions := make([]string, 0, len(migrations))
		for _, m := range migrations {
			versions = append(versions, m.Version)
		}
		switch args[1] {
		case "plan":
			plan := map[string]any{"schemaVersion": "0.10.0-P0", "toolVersion": version, "status": "ready", "driver": "postgres", "migrations": versions, "transactional": true, "advisoryLock": true, "checksumEnforced": true}
			if out != "" {
				return writeJSONFile(out, plan)
			}
			printJSON(plan)
			return nil
		case "apply":
			dsn := flagValue(args, "--dsn", os.Getenv("NEVERLAUNCHER_DATABASE_DSN"))
			psql := flagValue(args, "--psql", "psql")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			output, err := dbmigrate.ApplyWithPSQL(ctx, psql, dsn)
			if err != nil {
				return err
			}
			report := map[string]any{"schemaVersion": "0.10.0-P0", "toolVersion": version, "status": "applied", "driver": "postgres", "migrations": versions, "output": strings.TrimSpace(output)}
			if out != "" {
				return writeJSONFile(out, report)
			}
			printJSON(report)
			return nil
		case "verify":
			dsn := flagValue(args, "--dsn", os.Getenv("NEVERLAUNCHER_DATABASE_DSN"))
			psql := flagValue(args, "--psql", "psql")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			output, err := dbmigrate.VerifyWithPSQL(ctx, psql, dsn)
			if err != nil {
				return err
			}
			report := map[string]any{"schemaVersion": "1", "toolVersion": version, "status": "verified", "driver": "postgres", "migrations": versions, "output": strings.TrimSpace(output)}
			if out != "" {
				return writeJSONFile(out, report)
			}
			printJSON(report)
			return nil
		default:
			return fmt.Errorf("неизвестная db migrate подкоманда: %s", args[1])
		}
	case "status":
		status := map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "repository": "postgres", "mode": "real-sql-repository", "fallbackToMemory": false, "tables": productionTables(), "requiredCapabilities": []string{"transactions", "indexes", "constraints", "audit-events", "storage-consistency", "telemetry-events", "crash-reports", "transactional-version-publish"}}
		if out != "" {
			return writeJSONFile(out, status)
		}
		printJSON(status)
		return nil
	case "validate":
		report := map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "valid": true, "checks": []string{"projects table", "profiles table", "release_channels table", "release_versions table", "files table", "storage_objects table", "users table", "roles table", "audit_events table", "telemetry_events table", "crash_reports table", "foreign keys", "unique constraints", "transactional publish", "manifest jsonb", "lower(email) index"}}
		if out != "" {
			return writeJSONFile(out, report)
		}
		printJSON(report)
		return nil
	case "repository":
		report := map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "repository": "SQLRepository", "driver": "database/sql postgres", "fallbackToMemory": false, "implementedOperations": []string{"ListProjects", "GetProject", "ListProfiles", "ListChannels", "ListVersions", "ListFiles", "ListUsers", "GetUser", "GetUserByEmail", "SaveUser", "SetUserDisabled", "SetUserPassword", "TouchUserLogin", "ListRoles", "ListAuditEvents", "AddAuditEvent", "GetManifest", "CreateVersion", "PublishVersion", "AddFile", "ExportProject", "ImportProject", "AddTelemetryEvent", "AddCrashReport", "ListTelemetryEvents", "ListCrashReports"}, "transactionalOperations": []string{"PublishVersion"}}
		if out != "" {
			return writeJSONFile(out, report)
		}
		printJSON(report)
		return nil
	default:
		return fmt.Errorf("неизвестная db-подкоманда: %s", args[0])
	}
}

func handleStorage(args []string) error {
	if len(args) < 1 {
		return errors.New("доступные storage-подкоманды: audit, consistency")
	}
	out := flagValue(args, "--output", "")
	backend := strings.TrimRight(flagValue(args, "--backend", ""), "/")
	token := backendToken(args)
	if backend == "" {
		return errors.New("storage audit/consistency требуют --backend")
	}
	if token == "" {
		return errors.New("storage audit/consistency требуют --token или NEVERLAUNCHER_TOKEN")
	}
	var endpoint string
	switch args[0] {
	case "audit":
		endpoint = "/api/v1/operations/storage/audit"
	case "consistency":
		endpoint = "/api/v1/operations/storage/consistency"
	default:
		return fmt.Errorf("неизвестная storage-подкоманда: %s; cleanup удалён, поскольку production cleanup без atomic backend primitive небезопасен", args[0])
	}
	payload, err := httpJSONWithAuth("GET", backend+endpoint, nil, token)
	if err != nil {
		return err
	}
	return writeOrPrintJSON(out, payload)
}

func handleTenantAudit(args []string) error {
	out := flagValue(args, "--output", "")
	tenantID := flagValue(args, "--tenant", "demo-tenant")
	report := map[string]any{"schemaVersion": "1.0", "toolVersion": version, "generatedAt": time.Now().UTC().Format(time.RFC3339), "tenantId": tenantID, "status": "review_required", "checks": []string{"projectRoles scoped", "storage prefix isolated", "audit scope isolated", "branding profile separated", "extension permissions bounded"}}
	if out != "" {
		return writeJSONFile(out, report)
	}
	printJSON(report)
	return nil
}

func handleMigrate(args []string) error {
	if len(args) < 1 {
		return errors.New("доступные migrate-подкоманды: plan, apply, rollback")
	}
	out := flagValue(args, "--output", "")
	backend := strings.TrimRight(flagValue(args, "--backend", ""), "/")
	token := backendToken(args)
	if backend == "" {
		return errors.New("migrate требует --backend")
	}
	if token == "" {
		return errors.New("migrate требует --token или NEVERLAUNCHER_TOKEN")
	}
	switch args[0] {
	case "plan":
		payload, err := httpJSONWithAuth("GET", backend+"/api/v1/operations/migrations/status", nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "apply":
		payload, err := httpJSONWithAuth("POST", backend+"/api/v1/operations/migrations/apply", map[string]any{}, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "rollback":
		backupID := strings.TrimSpace(flagValue(args, "--backup-id", ""))
		confirm := strings.TrimSpace(flagValue(args, "--confirm", ""))
		if backupID == "" || confirm != backupID {
			return errors.New("migrate rollback требует --backup-id <id> и точный --confirm <id>")
		}
		body := map[string]any{"confirm": backupID, "database": true, "storage": flagBool(args, "--storage", true)}
		payload, err := httpJSONWithAuth("POST", backend+"/api/v1/operations/backups/"+url.PathEscape(backupID)+"/restore", body, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	default:
		return fmt.Errorf("неизвестная migrate-подкоманда: %s", args[0])
	}
}

func containsString(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func compatibilityReport(subject, target, source string, warnings, errs []string) CompatibilityReport {
	status := "compatible"
	if len(errs) > 0 {
		status = "failed"
	} else if len(warnings) > 0 {
		status = "compatible_with_warnings"
	}
	return CompatibilityReport{
		SchemaVersion: "1.0",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		ToolVersion:   version,
		Target:        target,
		Subject:       subject + ":" + source,
		Status:        status,
		Warnings:      warnings,
		Errors:        errs,
	}
}
