package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

type gravitOptionalPreviewRequest02411 struct {
	ExpectedRevision uint64          `json:"expectedRevision"`
	Source           json.RawMessage `json:"source"`
}

// Это пробное преобразование недоверенных данных Gravit. Результат можно сохранить
// только через существующую транзакцию PUT каталога компонентов, повторно
// вычисляющую хеш, проверяющую все пресеты и ревизию CAS.
func (s Server) componentCatalogGravitPreview02411(w http.ResponseWriter, r *http.Request) {
	lookup, err := editorLookup0248(s, r.PathValue("packageId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "Пакет не найден")
		return
	}
	if lookup.Release.Status != "draft" || lookup.Release.Manifest.SchemaVersion != model.ManifestSchemaV3 {
		writeError(w, http.StatusConflict, "Для миграции Gravit требуется неподписанный черновик Manifest v3")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	var req gravitOptionalPreviewRequest02411
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err = d.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var trailing any
	if err = d.Decode(&trailing); err != io.EOF {
		writeError(w, http.StatusBadRequest, "Неожиданные данные в конце запроса")
		return
	}
	existing := lookup.Release.Manifest.ComponentCatalog
	if existing == nil || req.ExpectedRevision == 0 || req.ExpectedRevision != existing.Revision {
		writeError(w, http.StatusConflict, "Ревизия каталога изменилась; обновите данные перед импортом")
		return
	}
	if len(req.Source) == 0 {
		writeError(w, http.StatusBadRequest, "Требуется источник Gravit")
		return
	}
	source := []byte(req.Source)
	if len(source) > 0 && source[0] == '"' {
		var verbatim string
		if err := json.Unmarshal(source, &verbatim); err != nil {
			writeError(w, http.StatusBadRequest, "Некорректная строка источника")
			return
		}
		source = []byte(verbatim)
	}
	result, err := model.ConvertGravitOptionalView02411(source, *existing, lookup.Release.Manifest.Files)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, preview := previewCatalog0248(lookup.Release, componentEditorRequest0248{ExpectedRevision: req.ExpectedRevision, Catalog: result.Catalog})
	if len(preview.Errors) != 0 {
		for _, msg := range preview.Errors {
			result.Fields = append(result.Fields, model.GravitFieldResult02210{Field: "catalog", Status: "blocked", Reason: msg})
			result.Summary["blocked"]++
		}
		result.Ready = false
	}
	// Явно запрещайте незаметное объединение неподдерживаемой семантики с
	// допустимым кандидатом. Перед обычным сохранением администратор обязан
	// рассмотреть и устранить каждую проблему.
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"migration": result, "preview": preview, "canApply": result.Ready && preview.Valid, "warning": strings.Join(preview.Errors, "; ")}})
}
