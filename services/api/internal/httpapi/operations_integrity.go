package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/dbmigrate"
)

func (s Server) operationsStorageAudit(w http.ResponseWriter, r *http.Request) {
	unlock := s.beginMaintenanceExclusive()
	defer unlock()
	report, consistent := s.storageIntegrityReport(r.Context())
	status := http.StatusOK
	if !consistent {
		status = http.StatusConflict
	}
	writeJSON(w, status, report)
}

func (s Server) operationsStorageConsistency(w http.ResponseWriter, r *http.Request) {
	unlock := s.beginMaintenanceExclusive()
	defer unlock()
	report, consistent := s.storageIntegrityReport(r.Context())
	report["mode"] = "strict-consistency"
	status := http.StatusOK
	if !consistent {
		status = http.StatusConflict
	}
	writeJSON(w, status, report)
}

func (s Server) storageIntegrityReport(ctx context.Context) (map[string]any, bool) {
	type problem struct {
		ProjectID string `json:"projectId,omitempty"`
		VersionID string `json:"versionId,omitempty"`
		Path      string `json:"path"`
		Kind      string `json:"kind"`
		Message   string `json:"message"`
	}
	problems := []problem{}
	expected := map[string]struct{}{}
	checked := 0
	for _, project := range s.Repo.ListProjects() {
		versions, err := s.Repo.ListVersions(project.ID)
		if err != nil {
			problems = append(problems, problem{ProjectID: project.ID, Kind: "repository", Message: err.Error()})
			continue
		}
		for _, version := range versions {
			files, err := s.Repo.ListFiles(project.ID, version.ID)
			if err != nil {
				problems = append(problems, problem{ProjectID: project.ID, VersionID: version.ID, Kind: "repository", Message: err.Error()})
				continue
			}
			for _, item := range files {
				select {
				case <-ctx.Done():
					problems = append(problems, problem{ProjectID: project.ID, VersionID: version.ID, Path: item.Path, Kind: "timeout", Message: ctx.Err().Error()})
					continue
				default:
				}
				expected[filepath.ToSlash(filepath.Join(project.ID, version.ID, filepath.FromSlash(item.Path)))] = struct{}{}
				reader, size, err := s.Storage.Open(project.ID, version.ID, item.Path)
				if err != nil {
					problems = append(problems, problem{ProjectID: project.ID, VersionID: version.ID, Path: item.Path, Kind: "missing", Message: err.Error()})
					continue
				}
				h := sha256.New()
				_, copyErr := io.Copy(h, reader)
				closeErr := reader.Close()
				checked++
				if copyErr != nil || closeErr != nil {
					problems = append(problems, problem{ProjectID: project.ID, VersionID: version.ID, Path: item.Path, Kind: "read", Message: fmt.Sprintf("copy=%v close=%v", copyErr, closeErr)})
					continue
				}
				actual := hex.EncodeToString(h.Sum(nil))
				if size != item.Size || !strings.EqualFold(actual, item.SHA256) {
					problems = append(problems, problem{ProjectID: project.ID, VersionID: version.ID, Path: item.Path, Kind: "checksum", Message: fmt.Sprintf("size=%d expected=%d sha256=%s expectedSha256=%s", size, item.Size, actual, item.SHA256)})
				}
			}
		}
	}

	orphanScan := "unsupported-for-" + s.Storage.Driver()
	orphans := []string{}
	if local, ok := s.Storage.(interface{ RootPath() string }); ok {
		orphanScan = "complete"
		root := local.RootPath()
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				problems = append(problems, problem{Path: path, Kind: "walk", Message: err.Error()})
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return nil
			}
			rel = filepath.ToSlash(rel)
			if _, ok := expected[rel]; !ok {
				orphans = append(orphans, rel)
			}
			return nil
		})
		sort.Strings(orphans)
		for _, orphan := range orphans {
			problems = append(problems, problem{Path: orphan, Kind: "orphan", Message: "объект отсутствует в repository metadata"})
		}
	}

	consistent := len(problems) == 0
	status := "consistent"
	if !consistent {
		status = "inconsistent"
	}
	return map[string]any{
		"schemaVersion":     apiContractVersion,
		"toolVersion":       s.Version,
		"generatedAt":       time.Now().UTC().Format(time.RFC3339),
		"status":            status,
		"storageDriver":     s.Storage.Driver(),
		"checkedObjects":    checked,
		"referencedObjects": len(expected),
		"orphanScan":        orphanScan,
		"orphanObjects":     orphans,
		"problems":          problems,
	}, consistent
}

func (s Server) operationsMigrationsStatus(w http.ResponseWriter, r *http.Request) {
	migrator, ok := s.Repo.(interface {
		MigrationStatus(context.Context) (dbmigrate.Status, error)
	})
	if !ok {
		writeError(w, http.StatusBadRequest, "repository не поддерживает SQL migrations")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	status, err := migrator.MigrationStatus(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "status": status})
}

func (s Server) operationsMigrationsApply(w http.ResponseWriter, r *http.Request) {
	migrator, ok := s.Repo.(interface {
		ApplyMigrations(context.Context) (dbmigrate.Status, error)
	})
	if !ok {
		writeError(w, http.StatusBadRequest, "repository не поддерживает SQL migrations")
		return
	}
	unlock := s.beginMaintenanceExclusive()
	defer unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	status, err := migrator.ApplyMigrations(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "migrations:apply", status.Current)
	writeJSON(w, http.StatusOK, map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "status": "applied", "migration": status})
}
