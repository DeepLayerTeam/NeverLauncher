package httpapi

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"strings"
)

func (s Server) projects(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.Repo.ListProjects()})
}

func (s Server) project(w http.ResponseWriter, r *http.Request) {
	project, err := s.Repo.GetProject(r.PathValue("projectId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "проект не найден")
		return
	}
	writeJSON(w, http.StatusOK, project)
}

func (s Server) profiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := s.Repo.ListProfiles(r.PathValue("projectId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "проект не найден")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": profiles})
}

func (s Server) channels(w http.ResponseWriter, r *http.Request) {
	channels, err := s.Repo.ListChannels(r.PathValue("projectId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "проект не найден")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": channels})
}

func (s Server) versions(w http.ResponseWriter, r *http.Request) {
	versions, err := s.Repo.ListVersions(r.PathValue("projectId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "проект не найден")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": versions})
}

func (s Server) files(w http.ResponseWriter, r *http.Request) {
	files, err := s.Repo.ListFiles(r.PathValue("projectId"), r.URL.Query().Get("versionId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "проект не найден")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": files})
}

func (s Server) manifest(w http.ResponseWriter, r *http.Request) {
	channel := r.URL.Query().Get("channel")
	if channel == "" {
		channel = "stable"
	}
	manifest, err := s.Repo.GetManifest(r.PathValue("projectId"), r.PathValue("profileId"), channel)
	if err != nil {
		writeError(w, http.StatusNotFound, "манифест не найден")
		return
	}
	writeJSON(w, http.StatusOK, manifest)
}

func (s Server) file(w http.ResponseWriter, r *http.Request) {
	reader, size, err := s.Storage.Open(r.PathValue("projectId"), r.PathValue("version"), r.PathValue("path"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || strings.Contains(strings.ToLower(err.Error()), "не найден") {
			writeError(w, http.StatusNotFound, "файл не найден")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer reader.Close()

	if size >= 0 {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	if _, err := io.Copy(w, reader); err != nil {
		log.Printf("не удалось отдать файл: %v", err)
	}
}
