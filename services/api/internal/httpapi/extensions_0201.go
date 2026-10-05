package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

func (s Server) adminExtensions0201(w http.ResponseWriter, r *http.Request) {
	items, err := s.Repo.ListExtensions(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": "2.0", "items": items}})
}

func (s Server) adminExtension0201(w http.ResponseWriter, r *http.Request) {
	id := strings.ToLower(strings.TrimSpace(r.PathValue("extensionId")))
	item, err := s.Repo.GetExtension(r.Context(), id)
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusNotFound, "extension не найден")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": "2.0", "extension": item}})
}

func (s Server) adminExtensionVersions0201(w http.ResponseWriter, r *http.Request) {
	id := strings.ToLower(strings.TrimSpace(r.PathValue("extensionId")))
	items, err := s.Repo.ListExtensionVersions(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": "2.0", "extensionId": id, "items": items}})
}

func (s Server) adminExtensionVersion0201(w http.ResponseWriter, r *http.Request) {
	id := strings.ToLower(strings.TrimSpace(r.PathValue("extensionId")))
	version := strings.TrimSpace(r.PathValue("version"))
	item, err := s.Repo.GetExtensionVersion(r.Context(), id, version)
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusNotFound, "extension version не найдена")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": "2.0", "version": item}})
}

func (s Server) adminExtensionVersionRegister0201(w http.ResponseWriter, r *http.Request) {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var manifest model.ExtensionManifest
	if err := dec.Decode(&manifest); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный neverlauncher-extension.json: "+err.Error())
		return
	}
	item, err := s.Repo.SaveExtensionVersion(r.Context(), manifest)
	if errors.Is(err, repository.ErrImmutable) || errors.Is(err, repository.ErrConflict) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "extension:version:register", item.ExtensionID+"@"+item.Version)
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": "2.0", "version": item, "status": "registered"}})
}
