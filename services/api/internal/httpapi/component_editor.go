package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

// Изменения ComponentEditor сериализуются той же блокировкой пакета, что загрузка и
// подпись. CAS по ревизии не позволяет одному администратору перезаписать действия
// другого. Backend выполняет авторитетную проверку и вычисляет подписанный хеш.
type componentEditorRequest0248 struct {
	ExpectedRevision uint64                     `json:"expectedRevision"`
	Catalog          model.ComponentCatalog0241 `json:"catalog"`
}
type componentPreviewEntry0248 struct {
	Preset   string   `json:"preset"`
	Selected []string `json:"selected,omitempty"`
	Error    string   `json:"error,omitempty"`
}
type componentPreview0248 struct {
	Valid    bool                        `json:"valid"`
	Digest   string                      `json:"digest"`
	Revision uint64                      `json:"revision"`
	Errors   []string                    `json:"errors"`
	Presets  []componentPreviewEntry0248 `json:"presets"`
}

func editorLookup0248(s Server, packageID string) (packageLookup, error) {
	// Допустима только каноническая идентичность пакета: псевдонимы по одной
	// версии неоднозначны между проектами и не должны выбирать другой выпуск.
	lookup, err := s.lookupPackage(packageID)
	if err != nil {
		return packageLookup{}, err
	}
	if lookup.Release.ID != packageID {
		return packageLookup{}, repository.ErrNotFound
	}
	return lookup, nil
}

func (s Server) componentCatalogGet0248(w http.ResponseWriter, r *http.Request) {
	lookup, err := editorLookup0248(s, r.PathValue("packageId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "Пакет не найден")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"packageId": lookup.Release.ID, "projectId": lookup.Release.ProjectID,
		"status": lookup.Release.Status, "manifestSchemaVersion": lookup.Release.Manifest.SchemaVersion,
		"catalog": lookup.Release.Manifest.ComponentCatalog, "files": lookup.Release.Manifest.Files,
	}})
}

func readCatalogRequest0248(w http.ResponseWriter, r *http.Request) (componentEditorRequest0248, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	var req componentEditorRequest0248
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil {
		return req, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return req, errors.New("Неожиданное значение: лишний JSON")
	}
	if req.ExpectedRevision == 0 {
		return req, errors.New("Требуется: expectedRevision")
	}
	if req.Catalog.SchemaVersion != model.ComponentCatalogSchema0245 {
		return req, errors.New("редактор компонентов: требуется «схема подписанного каталога 5.0»")
	}
	return req, nil
}

func previewCatalog0248(release model.ReleaseVersion, req componentEditorRequest0248) (model.ComponentCatalog0241, componentPreview0248) {
	cat := model.NewComponentCatalog0245(req.Catalog, req.ExpectedRevision+1)
	report := componentPreview0248{Valid: true, Digest: cat.Digest, Revision: cat.Revision, Errors: []string{}, Presets: []componentPreviewEntry0248{}}
	candidate := release.Manifest
	candidate.ComponentCatalog = &cat
	if release.Manifest.SchemaVersion != model.ManifestSchemaV3 {
		report.Errors = append(report.Errors, "Пакет необходимо создать с манифестом v3")
	} else if err := model.ValidateManifestSchema(candidate); err != nil {
		report.Errors = append(report.Errors, err.Error())
	}
	// Проверяйте топологию всех явных пресетов настоящим детерминированным
	// разрешителем графа, а не приближённой проверкой интерфейса. Условия отдельно
	// проверяются при запуске по доверенной среде и правам доступа.
	if len(report.Errors) == 0 {
		for _, name := range append([]string{""}, presetIDs0248(cat)...) {
			entry := componentPreviewEntry0248{Preset: name}
			result, err := model.PreviewCatalogGraph0248(cat, name)
			if err != nil {
				entry.Error = err.Error()
				report.Errors = append(report.Errors, fmt.Sprintf("preset %q: %v", name, err))
			} else {
				entry.Selected = result
			}
			report.Presets = append(report.Presets, entry)
		}
	}
	report.Valid = len(report.Errors) == 0
	return cat, report
}
func presetIDs0248(cat model.ComponentCatalog0241) []string {
	names := make([]string, 0, len(cat.Presets))
	for _, p := range cat.Presets {
		names = append(names, p.ID)
	}
	return names
}

func (s Server) componentCatalogPreview0248(w http.ResponseWriter, r *http.Request) {
	lookup, err := editorLookup0248(s, r.PathValue("packageId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "Пакет не найден")
		return
	}
	req, err := readCatalogRequest0248(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if lookup.Release.Status != "draft" {
		writeError(w, http.StatusConflict, "Каталог можно редактировать только до подписания")
		return
	}
	if lookup.Release.Manifest.ComponentCatalog == nil || lookup.Release.Manifest.ComponentCatalog.Revision != req.ExpectedRevision {
		writeError(w, http.StatusConflict, "Каталог изменился: обновите данные перед редактированием")
		return
	}
	_, report := previewCatalog0248(lookup.Release, req)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": report})
}

func (s Server) componentCatalogSave0248(w http.ResponseWriter, r *http.Request) {
	// Сериализуйте операции с подписью и загрузкой пакета, а также другими
	// изменениями компонентов.
	lookup, unlock, err := s.lockPackageLookupMutation(r.Context(), r.PathValue("packageId"))
	if err != nil {
		writeError(w, http.StatusConflict, "Пакет занят или отсутствует")
		return
	}
	defer unlock()
	if lookup.Release.ID != r.PathValue("packageId") {
		writeError(w, http.StatusNotFound, "Пакет не найден")
		return
	}
	if lookup.Release.Status != "draft" {
		writeError(w, http.StatusConflict, "Подписанный, подготовленный или опубликованный пакет нельзя изменять")
		return
	}
	req, err := readCatalogRequest0248(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if lookup.Release.Manifest.ComponentCatalog == nil || lookup.Release.Manifest.ComponentCatalog.Revision != req.ExpectedRevision {
		writeError(w, http.StatusConflict, "Ревизия каталога изменилась; обновите данные перед редактированием")
		return
	}
	cat, report := previewCatalog0248(lookup.Release, req)
	if !report.Valid {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"apiVersion": apiContractVersion, "error": map[string]any{"message": strings.Join(report.Errors, "; ")}, "preview": report})
		return
	}
	updater, ok := s.Repo.(interface {
		UpdateDraftComponentCatalog0248(string, string, uint64, model.ComponentCatalog0241) (model.ReleaseVersion, error)
	})
	if !ok {
		writeError(w, http.StatusInternalServerError, "Обновление хранилища каталога недоступно")
		return
	}
	updated, err := updater.UpdateDraftComponentCatalog0248(lookup.Release.ProjectID, lookup.Release.ID, req.ExpectedRevision, cat)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "component-catalog:update", lookup.Release.ID)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"catalog": updated.Manifest.ComponentCatalog, "status": updated.Status, "preview": report,
	}})
}
