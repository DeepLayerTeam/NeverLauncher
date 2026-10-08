package httpapi

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

type operationsBackupFile880 struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type operationsBackupManifest880 struct {
	SchemaVersion  string                    `json:"schemaVersion"`
	ToolVersion    string                    `json:"toolVersion"`
	BackupID       string                    `json:"backupId"`
	CreatedAt      string                    `json:"createdAt"`
	Mode           string                    `json:"mode"`
	Repository     string                    `json:"repository"`
	Storage        string                    `json:"storage"`
	DatabaseDump   bool                      `json:"databaseDump"`
	StorageObjects int                       `json:"storageObjects"`
	Files          []operationsBackupFile880 `json:"files"`
	Counts         map[string]int            `json:"counts"`
}

type operationsBackupRestoreRequest880 struct {
	Confirm  string `json:"confirm"`
	Database bool   `json:"database"`
	Storage  bool   `json:"storage"`
}

func (s Server) operationsBackupStatus(w http.ResponseWriter, r *http.Request) {
	backups, err := s.listOperationsBackups880()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schemaVersion": apiContractVersion,
		"toolVersion":   s.Version,
		"status":        "product-ready",
		"mode":          "archive-backed",
		"backupRoot":    s.operationsBackupRoot880(),
		"backups":       backups,
		"capabilities": []string{
			"atomic-tar-gz", "manifest-sha256", "postgres-custom-dump", "storage-object-backup",
			"audit-hash-chain", "redacted-diagnostics", "restore-dry-run", "confirmed-database-restore", "confirmed-storage-restore",
		},
	})
}

func (s Server) operationsBackupCreate(w http.ResponseWriter, r *http.Request) {
	unlock := s.beginMaintenanceExclusive()
	defer unlock()
	backup, err := s.createOperationsBackup880(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "backup:create", backup["backupId"].(string))
	writeJSON(w, http.StatusCreated, backup)
}

func (s Server) operationsBackupGet(w http.ResponseWriter, r *http.Request) {
	backupID, err := validateBackupID880(r.PathValue("backupId"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	path := filepath.Join(s.operationsBackupRoot880(), backupID+".tar.gz")
	manifest, err := inspectOperationsBackup880(path)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	sha, size, err := hashFile880(path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "backupId": backupID, "archive": path, "size": size, "sha256": sha, "manifest": manifest})
}

func (s Server) operationsBackupRestoreDryRun(w http.ResponseWriter, r *http.Request) {
	backupID, err := validateBackupID880(r.PathValue("backupId"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	path := filepath.Join(s.operationsBackupRoot880(), backupID+".tar.gz")
	report, err := s.verifyOperationsBackup880(r.Context(), path, backupID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "backup:restore-dry-run", backupID)
	writeJSON(w, http.StatusOK, report)
}

func (s Server) operationsBackupRestore(w http.ResponseWriter, r *http.Request) {
	backupID, err := validateBackupID880(r.PathValue("backupId"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req operationsBackupRestoreRequest880
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "restore требует JSON с confirm/database/storage")
		return
	}
	if strings.TrimSpace(req.Confirm) != backupID {
		writeError(w, http.StatusBadRequest, "для restore поле confirm должно точно совпадать с backupId")
		return
	}
	if !req.Database && !req.Storage {
		writeError(w, http.StatusBadRequest, "restore требует database=true и/или storage=true")
		return
	}
	unlock := s.beginMaintenanceExclusive()
	defer unlock()

	// Перед destructive restore создаётся самостоятельный safety backup в том же
	// maintenance-window. PostgreSQL restore выполняется одной транзакцией, а
	// local-storage переключается атомарным rename каталога.
	safety, safetyErr := s.createOperationsBackup880(r.Context())
	if safetyErr != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать обязательный safety backup перед restore: "+safetyErr.Error())
		return
	}
	safetyID, _ := safety["backupId"].(string)

	path := filepath.Join(s.operationsBackupRoot880(), backupID+".tar.gz")
	workDir, manifest, err := extractAndVerifyOperationsBackup880(path, backupID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer os.RemoveAll(workDir)

	restored := make([]string, 0, 2)
	if req.Database {
		if !manifest.DatabaseDump {
			writeError(w, http.StatusBadRequest, "backup не содержит PostgreSQL dump")
			return
		}
		if err := restorePostgresDump880(r.Context(), s.Config.DatabaseDSN, filepath.Join(workDir, "database.dump")); err != nil {
			writeError(w, http.StatusInternalServerError, "восстановление PostgreSQL не выполнено; safety backup="+safetyID+": "+err.Error())
			return
		}
		restored = append(restored, "database")
	}
	if req.Storage {
		count, err := s.restoreStorageObjects880(workDir)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "восстановление storage не выполнено; safety backup="+safetyID+": "+err.Error())
			return
		}
		restored = append(restored, fmt.Sprintf("storage:%d", count))
	}
	s.audit(r, s.adminActor(r), "backup:restore", backupID+":"+strings.Join(restored, ","))
	writeJSON(w, http.StatusOK, map[string]any{
		"schemaVersion":  apiContractVersion,
		"toolVersion":    s.Version,
		"status":         "restored",
		"backupId":       backupID,
		"safetyBackupId": safetyID,
		"restored":       restored,
		"completedAt":    time.Now().UTC().Format(time.RFC3339),
	})
}

func (s Server) operationsAuditExport(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.auditExportPayload880())
}

func (s Server) operationsDiagnosticsBundle(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.diagnosticsBundlePayload880())
}

func (s Server) adminCompliance(w http.ResponseWriter, r *http.Request) {
	backups, _ := s.listOperationsBackups880()
	writeJSON(w, http.StatusOK, map[string]any{
		"schemaVersion": apiContractVersion,
		"toolVersion":   s.Version,
		"status":        "compliance-hardened",
		"audit":         map[string]any{"events": len(s.Repo.ListAuditEvents()), "export": "/api/v1/operations/audit/export", "hashChain": true},
		"backup":        map[string]any{"count": len(backups), "root": s.operationsBackupRoot880(), "restoreDryRun": true, "restore": true},
		"diagnostics":   map[string]any{"redacted": true, "endpoint": "/api/v1/operations/diagnostics-bundle"},
		"metrics":       []string{"neverlauncher_backups_total", "neverlauncher_audit_events_total", "neverlauncher_telemetry_events_total", "neverlauncher_crash_reports_total"},
	})
}

func (s Server) createOperationsBackup880(ctx context.Context) (map[string]any, error) {
	backupID := "backup-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	root := s.operationsBackupRoot880()
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("не удалось создать backup root: %w", err)
	}
	stage, err := os.MkdirTemp(root, ".stage-"+backupID+"-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0o700); err != nil {
		return nil, err
	}

	if err := writeJSONBackupFile880(filepath.Join(stage, "repository-snapshot.json"), s.repositorySnapshotPayload880()); err != nil {
		return nil, err
	}
	if err := writeJSONBackupFile880(filepath.Join(stage, "audit-export.json"), s.auditExportPayload880()); err != nil {
		return nil, err
	}
	if err := writeJSONBackupFile880(filepath.Join(stage, "diagnostics-bundle.json"), s.diagnosticsBundlePayload880()); err != nil {
		return nil, err
	}
	if err := writeJSONBackupFile880(filepath.Join(stage, "config-redacted.json"), s.redactedConfigPayload880()); err != nil {
		return nil, err
	}

	databaseDump := false
	if isPostgresRepository880(s.Config.RepositoryDriver) {
		if err := createPostgresDump880(ctx, s.Config.DatabaseDSN, filepath.Join(stage, "database.dump")); err != nil {
			return nil, fmt.Errorf("pg_dump не выполнен: %w", err)
		}
		databaseDump = true
	}
	storageCount, err := s.backupStorageObjects880(stage)
	if err != nil {
		return nil, err
	}

	manifest := operationsBackupManifest880{
		SchemaVersion:  apiContractVersion,
		ToolVersion:    s.Version,
		BackupID:       backupID,
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
		Mode:           "full-product-backup",
		Repository:     s.Config.RepositoryDriver,
		Storage:        s.Storage.Driver(),
		DatabaseDump:   databaseDump,
		StorageObjects: storageCount,
		Counts: map[string]int{
			"projects":        len(s.Repo.ListProjects()),
			"users":           len(s.Repo.ListUsers()),
			"roles":           len(s.Repo.ListRoles()),
			"auditEvents":     len(s.Repo.ListAuditEvents()),
			"telemetryEvents": len(s.Repo.ListTelemetryEvents()),
			"crashReports":    len(s.Repo.ListCrashReports()),
		},
	}
	manifest.Files, err = collectBackupFiles880(stage)
	if err != nil {
		return nil, err
	}
	if err := writeJSONBackupFile880(filepath.Join(stage, "manifest.json"), manifest); err != nil {
		return nil, err
	}

	archivePath := filepath.Join(root, backupID+".tar.gz")
	tmpArchive := archivePath + ".tmp"
	if err := writeOperationsBackupArchive880(tmpArchive, stage); err != nil {
		_ = os.Remove(tmpArchive)
		return nil, err
	}
	if err := os.Rename(tmpArchive, archivePath); err != nil {
		_ = os.Remove(tmpArchive)
		return nil, err
	}
	archiveSum, archiveSize, err := hashFile880(archivePath)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"schemaVersion": apiContractVersion,
		"toolVersion":   s.Version,
		"status":        "created",
		"backupId":      backupID,
		"archive":       archivePath,
		"size":          archiveSize,
		"sha256":        archiveSum,
		"manifest":      manifest,
		"restoreDryRun": "/api/v1/operations/backups/" + backupID + "/restore-dry-run",
		"restore":       "/api/v1/operations/backups/" + backupID + "/restore",
	}, nil
}

func (s Server) backupStorageObjects880(stage string) (int, error) {
	count := 0
	for _, project := range s.Repo.ListProjects() {
		versions, err := s.Repo.ListVersions(project.ID)
		if err != nil {
			return count, fmt.Errorf("не удалось перечислить версии %s: %w", project.ID, err)
		}
		for _, version := range versions {
			files, err := s.Repo.ListFiles(project.ID, version.ID)
			if err != nil {
				return count, fmt.Errorf("не удалось перечислить файлы %s/%s: %w", project.ID, version.ID, err)
			}
			for _, item := range files {
				reader, size, err := s.Storage.Open(project.ID, version.ID, item.Path)
				if err != nil {
					return count, fmt.Errorf("storage object %s/%s/%s недоступен: %w", project.ID, version.ID, item.Path, err)
				}
				rel := filepath.ToSlash(filepath.Join("storage", project.ID, version.ID, filepath.FromSlash(item.Path)))
				dst, err := safeBackupJoin880(stage, rel)
				if err != nil {
					reader.Close()
					return count, err
				}
				if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
					reader.Close()
					return count, err
				}
				out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
				if err != nil {
					reader.Close()
					return count, err
				}
				written, copyErr := io.Copy(out, reader)
				closeErr := out.Close()
				readerErr := reader.Close()
				if copyErr != nil {
					return count, copyErr
				}
				if closeErr != nil {
					return count, closeErr
				}
				if readerErr != nil {
					return count, readerErr
				}
				if size >= 0 && written != size {
					return count, fmt.Errorf("storage object %s имеет размер %d вместо %d", item.Path, written, size)
				}
				count++
			}
		}
	}
	return count, nil
}

func (s Server) restoreStorageObjects880(stage string) (int, error) {
	root := filepath.Join(stage, "storage")
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}

	// Local storage can be restored as an atomic directory switch because both
	// staging and live roots are prepared on the same filesystem. This also
	// removes objects created after the backup instead of leaving orphans.
	if local, ok := s.Storage.(interface{ RootPath() string }); ok {
		return restoreLocalStorageAtomic880(root, local.RootPath())
	}

	// S3-compatible storage does not provide an atomic prefix rename. The API is
	// still write-locked by maintenance mode, every object is checksum-verified
	// by backup extraction, and the safety backup created by the caller remains
	// available for operator rollback.
	return s.restoreStorageObjectsSequential880(root)
}

func (s Server) restoreStorageObjectsSequential880(root string) (int, error) {
	count := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) < 3 {
			return fmt.Errorf("некорректный storage path в backup: %s", rel)
		}
		projectID, versionID := parts[0], parts[1]
		relativePath := strings.Join(parts[2:], "/")
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, _, saveErr := s.Storage.Save(projectID, versionID, relativePath, file)
		closeErr := file.Close()
		if saveErr != nil {
			return saveErr
		}
		if closeErr != nil {
			return closeErr
		}
		count++
		return nil
	})
	return count, err
}

func restoreLocalStorageAtomic880(sourceRoot, liveRoot string) (int, error) {
	liveRoot = filepath.Clean(strings.TrimSpace(liveRoot))
	if liveRoot == "" || liveRoot == "." || liveRoot == string(os.PathSeparator) {
		return 0, fmt.Errorf("небезопасный local storage root для restore: %q", liveRoot)
	}
	absLive, err := filepath.Abs(liveRoot)
	if err != nil {
		return 0, err
	}
	if info, err := os.Lstat(absLive); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return 0, errors.New("local storage root не может быть symlink при atomic restore")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	parent := filepath.Dir(absLive)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return 0, err
	}
	stageRoot, err := os.MkdirTemp(parent, ".neverlauncher-restore-*")
	if err != nil {
		return 0, err
	}
	cleanupStage := true
	defer func() {
		if cleanupStage {
			_ = os.RemoveAll(stageRoot)
		}
	}()
	count, err := copyStorageTree880(sourceRoot, stageRoot)
	if err != nil {
		return 0, err
	}
	rollbackRoot := absLive + ".rollback-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	liveExists := false
	if _, err := os.Stat(absLive); err == nil {
		liveExists = true
		if err := os.Rename(absLive, rollbackRoot); err != nil {
			return 0, fmt.Errorf("не удалось подготовить atomic storage switch: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	if err := os.Rename(stageRoot, absLive); err != nil {
		if liveExists {
			_ = os.Rename(rollbackRoot, absLive)
		}
		return 0, fmt.Errorf("atomic storage switch не выполнен: %w", err)
	}
	cleanupStage = false
	if liveExists {
		if err := os.RemoveAll(rollbackRoot); err != nil {
			return count, fmt.Errorf("storage восстановлен, но не удалось удалить rollback directory %s: %w", rollbackRoot, err)
		}
	}
	return count, nil
}

func copyStorageTree880(srcRoot, dstRoot string) (int, error) {
	count := 0
	err := filepath.WalkDir(srcRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(srcRoot, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		dst := filepath.Join(dstRoot, rel)
		if entry.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return fmt.Errorf("storage backup содержит неподдерживаемый тип: %s", rel)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			in.Close()
			return err
		}
		_, copyErr := io.Copy(out, in)
		closeOut := out.Close()
		closeIn := in.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeOut != nil {
			return closeOut
		}
		if closeIn != nil {
			return closeIn
		}
		count++
		return nil
	})
	return count, err
}

func (s Server) repositorySnapshotPayload880() map[string]any {
	projects := s.Repo.ListProjects()
	projectPayloads := []map[string]any{}
	for _, project := range projects {
		profiles, _ := s.Repo.ListProfiles(project.ID)
		channels, _ := s.Repo.ListChannels(project.ID)
		versions, _ := s.Repo.ListVersions(project.ID)
		versionPayloads := []map[string]any{}
		for _, v := range versions {
			files, _ := s.Repo.ListFiles(project.ID, v.ID)
			versionPayloads = append(versionPayloads, map[string]any{"version": v, "files": files})
		}
		projectPayloads = append(projectPayloads, map[string]any{"project": project, "profiles": profiles, "channels": channels, "versions": versionPayloads})
	}
	users := []map[string]any{}
	for _, user := range s.Repo.ListUsers() {
		users = append(users, sanitizeUserForBackup880(user))
	}
	return map[string]any{
		"schemaVersion": apiContractVersion,
		"toolVersion":   s.Version,
		"createdAt":     time.Now().UTC().Format(time.RFC3339),
		"projects":      projectPayloads,
		"users":         users,
		"roles":         s.Repo.ListRoles(),
		"telemetry":     s.Repo.ListTelemetryEvents(),
		"crashReports":  s.Repo.ListCrashReports(),
	}
}

func (s Server) auditExportPayload880() map[string]any {
	events := s.Repo.ListAuditEvents()
	chain := make([]map[string]any, 0, len(events))
	prev := ""
	for _, event := range events {
		data, _ := json.Marshal(event)
		sum := sha256.Sum256(append([]byte(prev), data...))
		hash := hex.EncodeToString(sum[:])
		chain = append(chain, map[string]any{"event": event, "previousHash": prev, "eventHash": hash})
		prev = hash
	}
	return map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "createdAt": time.Now().UTC().Format(time.RFC3339), "mode": "append-only-hash-chain", "events": chain, "headHash": prev, "count": len(chain)}
}

func (s Server) diagnosticsBundlePayload880() map[string]any {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	checks := map[string]string{"storage": "ok", "repository": "not_applicable"}
	if err := s.Storage.Health(ctx); err != nil {
		checks["storage"] = err.Error()
	}
	if checker, ok := s.Repo.(interface{ Health(context.Context) error }); ok {
		if err := checker.Health(ctx); err != nil {
			checks["repository"] = err.Error()
		} else {
			checks["repository"] = "ok"
		}
	}
	return map[string]any{
		"schemaVersion": apiContractVersion,
		"toolVersion":   s.Version,
		"createdAt":     time.Now().UTC().Format(time.RFC3339),
		"redacted":      true,
		"config":        s.redactedConfigPayload880(),
		"checks":        checks,
		"counts": map[string]int{
			"projects":        len(s.Repo.ListProjects()),
			"users":           len(s.Repo.ListUsers()),
			"roles":           len(s.Repo.ListRoles()),
			"auditEvents":     len(s.Repo.ListAuditEvents()),
			"telemetryEvents": len(s.Repo.ListTelemetryEvents()),
			"crashReports":    len(s.Repo.ListCrashReports()),
		},
		"recommendedActions": []string{"проверить последний backup через restore-dry-run", "проверить /ready перед релизом", "экспортировать audit hash chain перед крупной миграцией"},
	}
}

func (s Server) redactedConfigPayload880() map[string]any {
	return map[string]any{
		"environment":         s.Config.Environment,
		"publicUrl":           s.Config.PublicURL,
		"repositoryDriver":    s.Config.RepositoryDriver,
		"sqlDriver":           s.Config.SQLDriver,
		"databaseDsn":         "<redacted>",
		"storageDriver":       s.Config.StorageDriver,
		"storageLocalPath":    s.Config.StorageLocalPath,
		"backupRoot":          s.Config.BackupRoot,
		"storageS3Endpoint":   s.Config.StorageS3Endpoint,
		"storageS3Bucket":     s.Config.StorageS3Bucket,
		"storageS3AccessKey":  redactIfSet880(s.Config.StorageS3AccessKey),
		"storageS3SecretKey":  redactIfSet880(s.Config.StorageS3SecretKey),
		"authTokenSecret":     redactIfSet880(s.Config.AuthTokenSecret),
		"storageDeliveryMode": s.Config.StorageDeliveryMode,
		"corsAllowedOrigins":  s.Config.CORSAllowedOrigins,
		"metricsEnabled":      s.Config.MetricsEnabled,
	}
}

func redactIfSet880(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return "<redacted>"
}

func sanitizeUserForBackup880(user model.User) map[string]any {
	return map[string]any{"id": user.ID, "email": user.Email, "displayName": user.DisplayName, "roleId": user.RoleID, "status": user.Status, "projectRoles": user.ProjectRoles, "passwordHash": "<redacted>", "passwordUpdatedAt": user.PasswordUpdatedAt, "lastLoginAt": user.LastLoginAt, "createdAt": user.CreatedAt, "updatedAt": user.UpdatedAt}
}

func (s Server) operationsBackupRoot880() string {
	root := strings.TrimSpace(s.Config.BackupRoot)
	if root == "" {
		root = "./data/backups"
	}
	return filepath.Clean(root)
}

func (s Server) listOperationsBackups880() ([]map[string]any, error) {
	root := s.operationsBackupRoot880()
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	items := []map[string]any{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tar.gz") {
			continue
		}
		path := filepath.Join(root, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}
		sha, size, err := hashFile880(path)
		if err != nil {
			continue
		}
		items = append(items, map[string]any{"backupId": strings.TrimSuffix(entry.Name(), ".tar.gz"), "archive": path, "size": size, "sha256": sha, "createdAt": info.ModTime().UTC().Format(time.RFC3339)})
	}
	sort.Slice(items, func(i, j int) bool { return fmt.Sprint(items[i]["backupId"]) > fmt.Sprint(items[j]["backupId"]) })
	return items, nil
}

func writeJSONBackupFile880(path string, payload any) error {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func collectBackupFiles880(root string) ([]operationsBackupFile880, error) {
	items := make([]operationsBackupFile880, 0)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Name() == "manifest.json" {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		sha, size, err := hashFile880(path)
		if err != nil {
			return err
		}
		items = append(items, operationsBackupFile880{Path: filepath.ToSlash(rel), Size: size, SHA256: sha})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })
	return items, nil
}

func writeOperationsBackupArchive880(path, root string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	cleanup := func() {
		_ = file.Close()
		_ = os.Remove(path)
	}
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	entries := make([]string, 0)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		entries = append(entries, filepath.ToSlash(rel))
		return nil
	}); err != nil {
		cleanup()
		return err
	}
	sort.Strings(entries)
	for _, rel := range entries {
		full, err := safeBackupJoin880(root, rel)
		if err != nil {
			cleanup()
			return err
		}
		info, err := os.Stat(full)
		if err != nil {
			cleanup()
			return err
		}
		hdr := &tar.Header{Name: rel, Mode: 0o600, Size: info.Size(), ModTime: info.ModTime().UTC(), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			cleanup()
			return err
		}
		in, err := os.Open(full)
		if err != nil {
			cleanup()
			return err
		}
		_, copyErr := io.Copy(tw, in)
		closeErr := in.Close()
		if copyErr != nil || closeErr != nil {
			cleanup()
			if copyErr != nil {
				return copyErr
			}
			return closeErr
		}
	}
	if err := tw.Close(); err != nil {
		cleanup()
		return err
	}
	if err := gz.Close(); err != nil {
		cleanup()
		return err
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func inspectOperationsBackup880(path string) (operationsBackupManifest880, error) {
	f, err := os.Open(path)
	if err != nil {
		return operationsBackupManifest880{}, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return operationsBackupManifest880{}, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return operationsBackupManifest880{}, err
		}
		if hdr.Name != "manifest.json" {
			continue
		}
		var manifest operationsBackupManifest880
		if err := json.NewDecoder(io.LimitReader(tr, 4<<20)).Decode(&manifest); err != nil {
			return operationsBackupManifest880{}, fmt.Errorf("manifest backup повреждён: %w", err)
		}
		return manifest, nil
	}
	return operationsBackupManifest880{}, errors.New("manifest.json отсутствует в backup archive")
}

func (s Server) verifyOperationsBackup880(ctx context.Context, path, backupID string) (map[string]any, error) {
	stage, manifest, err := extractAndVerifyOperationsBackup880(path, backupID)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)
	databaseDumpStatus := "absent"
	if manifest.DatabaseDump {
		databaseDumpStatus = "present"
		if _, err := exec.LookPath("pg_restore"); err == nil {
			cmdCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			cmd := exec.CommandContext(cmdCtx, "pg_restore", "--list", filepath.Join(stage, "database.dump"))
			if output, runErr := cmd.CombinedOutput(); runErr != nil {
				return nil, fmt.Errorf("pg_restore --list отклонил database.dump: %w: %s", runErr, strings.TrimSpace(string(output)))
			}
			databaseDumpStatus = "valid"
		} else {
			databaseDumpStatus = "present-pg_restore-unavailable"
		}
	}
	return map[string]any{
		"schemaVersion":  apiContractVersion,
		"toolVersion":    s.Version,
		"status":         "valid",
		"backupId":       manifest.BackupID,
		"checked":        len(manifest.Files),
		"databaseDump":   databaseDumpStatus,
		"storageObjects": manifest.StorageObjects,
		"restoreMode":    "dry-run",
		"wouldRestore":   []string{"PostgreSQL database.dump при database=true", "storage objects при storage=true"},
	}, nil
}

func extractAndVerifyOperationsBackup880(path, expectedBackupID string) (string, operationsBackupManifest880, error) {
	stage, err := os.MkdirTemp("", "neverlauncher-backup-verify-*")
	if err != nil {
		return "", operationsBackupManifest880{}, err
	}
	fail := func(err error) (string, operationsBackupManifest880, error) {
		_ = os.RemoveAll(stage)
		return "", operationsBackupManifest880{}, err
	}
	archive, err := os.Open(path)
	if err != nil {
		return fail(err)
	}
	defer archive.Close()
	gz, err := gzip.NewReader(archive)
	if err != nil {
		return fail(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	actual := map[string]operationsBackupFile880{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail(err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return fail(fmt.Errorf("backup archive содержит неподдерживаемый тип %d для %s", hdr.Typeflag, hdr.Name))
		}
		dst, err := safeBackupJoin880(stage, hdr.Name)
		if err != nil {
			return fail(err)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return fail(err)
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return fail(err)
		}
		h := sha256.New()
		written, copyErr := io.Copy(io.MultiWriter(out, h), tr)
		closeErr := out.Close()
		if copyErr != nil {
			return fail(copyErr)
		}
		if closeErr != nil {
			return fail(closeErr)
		}
		if written != hdr.Size {
			return fail(fmt.Errorf("размер %s не совпадает с tar header", hdr.Name))
		}
		actual[filepath.ToSlash(hdr.Name)] = operationsBackupFile880{Path: filepath.ToSlash(hdr.Name), Size: written, SHA256: hex.EncodeToString(h.Sum(nil))}
	}
	manifestData, err := os.ReadFile(filepath.Join(stage, "manifest.json"))
	if err != nil {
		return fail(errors.New("manifest.json отсутствует в backup archive"))
	}
	var manifest operationsBackupManifest880
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return fail(fmt.Errorf("manifest.json повреждён: %w", err))
	}
	if manifest.BackupID != expectedBackupID {
		return fail(fmt.Errorf("backupId в manifest (%s) не совпадает с ожидаемым %s", manifest.BackupID, expectedBackupID))
	}
	expected := make(map[string]operationsBackupFile880, len(manifest.Files))
	for _, item := range manifest.Files {
		if _, err := safeBackupJoin880(stage, item.Path); err != nil {
			return fail(err)
		}
		expected[item.Path] = item
		got, ok := actual[item.Path]
		if !ok {
			return fail(fmt.Errorf("%s отсутствует в backup archive", item.Path))
		}
		if got.Size != item.Size || !strings.EqualFold(got.SHA256, item.SHA256) {
			return fail(fmt.Errorf("%s: checksum/size mismatch", item.Path))
		}
	}
	for name := range actual {
		if name == "manifest.json" {
			continue
		}
		if _, ok := expected[name]; !ok {
			return fail(fmt.Errorf("backup archive содержит незаявленный файл %s", name))
		}
	}
	return stage, manifest, nil
}

func safeBackupJoin880(root, rel string) (string, error) {
	rel = filepath.ToSlash(strings.TrimSpace(rel))
	if rel == "" || rel == "." || strings.HasPrefix(rel, "/") || strings.Contains(rel, "\\") {
		return "", fmt.Errorf("небезопасный путь в backup archive: %q", rel)
	}
	clean := filepath.ToSlash(filepath.Clean(rel))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return "", fmt.Errorf("небезопасный путь в backup archive: %q", rel)
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	fullAbs, err := filepath.Abs(filepath.Join(root, filepath.FromSlash(clean)))
	if err != nil {
		return "", err
	}
	if fullAbs != rootAbs && !strings.HasPrefix(fullAbs, rootAbs+string(os.PathSeparator)) {
		return "", fmt.Errorf("backup path выходит за пределы staging root: %q", rel)
	}
	return fullAbs, nil
}

func createPostgresDump880(parent context.Context, dsn, output string) error {
	if _, err := exec.LookPath("pg_dump"); err != nil {
		return errors.New("pg_dump не найден; production backup требует postgresql-client")
	}
	env, _, err := postgresCommandEnvironment880(dsn)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "pg_dump", "--format=custom", "--no-owner", "--no-acl", "--file", output)
	cmd.Env = env
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pg_dump: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return os.Chmod(output, 0o600)
}

func restorePostgresDump880(parent context.Context, dsn, dumpPath string) error {
	if _, err := exec.LookPath("pg_restore"); err != nil {
		return errors.New("pg_restore не найден; production restore требует postgresql-client")
	}
	env, database, err := postgresCommandEnvironment880(dsn)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "pg_restore", "--exit-on-error", "--clean", "--if-exists", "--no-owner", "--no-acl", "--single-transaction", "--dbname", database, dumpPath)
	cmd.Env = env
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pg_restore: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func postgresCommandEnvironment880(dsn string) ([]string, string, error) {
	u, err := url.Parse(strings.TrimSpace(dsn))
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return nil, "", errors.New("NEVERLAUNCHER_DATABASE_DSN должен быть postgres:// или postgresql:// URL для backup/restore")
	}
	if u.Hostname() == "" || u.User == nil || u.User.Username() == "" {
		return nil, "", errors.New("PostgreSQL DSN должен содержать host и user")
	}
	database := strings.TrimPrefix(u.Path, "/")
	if database == "" || strings.Contains(database, "/") {
		return nil, "", errors.New("PostgreSQL DSN должен содержать имя базы данных")
	}
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	env := append([]string{}, os.Environ()...)
	env = append(env, "PGHOST="+u.Hostname(), "PGPORT="+port, "PGUSER="+u.User.Username(), "PGDATABASE="+database)
	if password, ok := u.User.Password(); ok {
		env = append(env, "PGPASSWORD="+password)
	}
	if sslmode := u.Query().Get("sslmode"); sslmode != "" {
		env = append(env, "PGSSLMODE="+sslmode)
	}
	return env, database, nil
}

func isPostgresRepository880(driver string) bool {
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "postgres", "postgresql", "sql":
		return true
	default:
		return false
	}
}

func validateBackupID880(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "/") || strings.Contains(value, "\\") || strings.Contains(value, "..") || !strings.HasPrefix(value, "backup-") {
		return "", errors.New("некорректный backupId")
	}
	return value, nil
}

func hashFile880(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

func backupsCount880(s Server) int {
	items, err := s.listOperationsBackups880()
	if err != nil {
		return 0
	}
	return len(items)
}
