package httpapi

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

// Рабочие пространства сборки доступны только оператору; загруженные данные
// хранятся под непубличными ключами с адресацией по содержимому до создания
// сборки.
const maxWorkspaceFiles0226 = 25000

func (s Server) workspaceStore0226(w http.ResponseWriter) (repository.BuildWorkspaceStore, bool) {
	store, ok := s.Repo.(repository.BuildWorkspaceStore)
	if !ok {
		writeError(w, 503, "Хранилище рабочих областей сборки недоступно")
	}
	return store, ok
}
func (s Server) ownedWorkspace0226(w http.ResponseWriter, r *http.Request, permission string) (repository.BuildWorkspaceStore, repository.BuildWorkspace, bool) {
	store, ok := s.workspaceStore0226(w)
	if !ok {
		return nil, repository.BuildWorkspace{}, false
	}
	ws, err := store.GetBuildWorkspace(r.Context(), r.PathValue("workspaceId"))
	if err != nil {
		writeError(w, 404, "Рабочая область не найдена")
		return store, ws, false
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "Требуется авторизация")
		return store, ws, false
	}
	if claims.Sub != ws.OwnerID || !s.authorizeClaims(r, claims, permission, ws.ProjectID, "project", ws.ProjectID).Allowed {
		writeError(w, 404, "Рабочая область не найдена")
		return store, ws, false
	}
	return store, ws, true
}
func readJSON0226(w http.ResponseWriter, r *http.Request, max int64, target any) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, max))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	var tail any
	if err := d.Decode(&tail); err != io.EOF {
		return errors.New("Ожидался ровно один объект JSON")
	}
	return nil
}
func (s Server) workspaceCreate0226(w http.ResponseWriter, r *http.Request) {
	store, ok := s.workspaceStore0226(w)
	if !ok {
		return
	}
	var req struct {
		ProjectID, ProfileID, Channel, Version string
		Settings                               repository.BuildSettings
	}
	if err := readJSON0226(w, r, 64<<10, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	req.ProjectID = strings.TrimSpace(req.ProjectID)
	req.ProfileID = strings.TrimSpace(req.ProfileID)
	req.Channel = strings.TrimSpace(req.Channel)
	req.Version = strings.TrimSpace(req.Version)
	if req.Channel == "" {
		req.Channel = "stable"
	}
	if req.ProjectID == "" || req.ProfileID == "" || req.Version == "" {
		writeError(w, 400, "Необходимо указать projectId, profileId и version")
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "Требуется авторизация")
		return
	}
	if !s.authorizeProjectAction(w, r, claims, "release:prepare", req.ProjectID, "project", req.ProjectID) {
		return
	}
	if _, err = s.Repo.GetProject(req.ProjectID); err != nil {
		writeError(w, 404, "Проект не найден")
		return
	}
	snapshot, err := repository.ReadProfileSnapshot(s.Repo, req.ProjectID, req.ProfileID)
	if err != nil {
		writeError(w, 400, "Профиль не найден или некорректен: "+err.Error())
		return
	}
	// Идентичность сервера не является отпечатком инструмента, задаваемым
	// пользователем.
	if req.Settings.ToolVersions == nil {
		req.Settings.ToolVersions = make(map[string]string)
	}
	if len(req.Settings.ToolVersions) > 32 {
		writeError(w, 400, "Превышено допустимое число инструментов")
		return
	}
	for k, v := range req.Settings.ToolVersions {
		if len(k) == 0 || len(k) > 128 || len(v) == 0 || len(v) > 128 || strings.ContainsAny(k+v, "\x00\r\n") {
			writeError(w, 400, "Некорректный отпечаток инструмента")
			return
		}
	}
	req.Settings.ToolVersions["launcher-api"] = s.Version
	if req.Settings.Minecraft.Version == "" {
		writeError(w, 400, "Необходимо указать версию Minecraft")
		return
	}
	if req.Settings.Minecraft.Loader == "" {
		req.Settings.Minecraft.Loader = snapshot.Spec.Loader
	}
	if !strings.EqualFold(req.Settings.Minecraft.Loader, snapshot.Spec.Loader) {
		writeError(w, 400, "Загрузчик рабочей области должен совпадать с закреплённым профилем клиента")
		return
	}
	if snapshot.Spec.MinecraftVersion != "" && req.Settings.Minecraft.LoaderVersion != snapshot.Spec.LoaderVersion {
		writeError(w, 409, "Конфигурация запуска не совпадает с профилем: требуется точная loaderVersion")
		return
	}
	if err := model.ValidateProfileLaunch0382(snapshot.Spec, req.Settings.Minecraft, req.Settings.Runtime.Java.MajorVersion, true); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if req.Settings.Runtime.Java.MajorVersion <= 0 {
		writeError(w, 400, "Требуется явное значение runtime.java.majorVersion")
		return
	}
	for _, v := range []string{req.ProjectID, req.ProfileID, req.Channel, req.Version} {
		if len(v) > 128 || strings.ContainsAny(v, "/\\\r\n\x00") {
			writeError(w, 400, "Некорректная область действия рабочей области")
			return
		}
	}
	// Проверьте Runtime и права владения до сохранения входных настроек. Записи
	// classpath/modulepath ссылаются на файлы, которые ещё не импортированы. После
	// размещения проверьте синтаксис и принадлежность по фактическим хешам.
	preflightRuntime := req.Settings.Runtime
	preflightRuntime.Launch.ClasspathEntries = nil
	preflightRuntime.Launch.ModulepathEntries = nil
	preflightRuntime.Launch.MainModule = ""
	probe := model.Manifest{SchemaVersion: model.ManifestSchemaV2, ProjectID: req.ProjectID, ProfileID: req.ProfileID, ProfileSnapshot: &snapshot, Minecraft: req.Settings.Minecraft, Runtime: preflightRuntime, Directories: req.Settings.Directories, FileRules: req.Settings.FileRules, Files: []model.ManifestFile{}}
	if err = model.ValidateManifestSchema(probe); err != nil {
		writeError(w, 400, "Некорректные настройки сборки: "+err.Error())
		return
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		writeError(w, 500, "Не удалось выделить идентификатор")
		return
	}
	ws := repository.BuildWorkspace{ID: "ws-" + hex.EncodeToString(id[:]), ProjectID: req.ProjectID, OwnerID: claims.Sub, ProfileID: req.ProfileID, Channel: req.Channel, Version: req.Version, ProfileRevision: snapshot.Revision, ProfileDigest: snapshot.Digest, Settings: req.Settings, Files: []repository.BuildFile{}}
	saved, err := store.CreateBuildWorkspace(r.Context(), ws)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	s.audit(r, claims.Sub, "build-workspace:create", saved.ID)
	w.Header().Set("Location", "/api/v1/build-workspaces/"+saved.ID)
	writeJSON(w, 201, map[string]any{"apiVersion": apiContractVersion, "data": saved})
}
func (s Server) workspaceList0226(w http.ResponseWriter, r *http.Request) {
	store, ok := s.workspaceStore0226(w)
	if !ok {
		return
	}
	projectID := r.URL.Query().Get("projectId")
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "Требуется авторизация")
		return
	}
	if !s.authorizeProjectAction(w, r, claims, "release:prepare", projectID, "project", projectID) {
		return
	}
	rows, err := store.ListBuildWorkspaces(r.Context(), projectID, claims.Sub)
	if err != nil {
		writeError(w, 503, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"items": rows}})
}
func (s Server) workspaceGet0226(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := s.ownedWorkspace0226(w, r, "release:prepare")
	if ok {
		writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": ws})
	}
}
func workspaceObjectPath0226(f repository.BuildFile) string { return "objects/" + f.SHA256 }
func normalizeBuildFile0226(f repository.BuildFile) error {
	if f.Ownership == "" {
		f.Ownership = "required"
	}
	if f.Ownership != "managed" && f.Ownership != "required" && f.Ownership != "optional" {
		return errors.New("Разрешена загрузка только управляемых, обязательных или необязательных файлов")
	}
	m := model.Manifest{SchemaVersion: model.ManifestSchemaV2, Files: []model.ManifestFile{{Path: f.Path, Required: f.Ownership != "optional", Ownership: f.Ownership}}}
	if err := model.ValidateFileOwnership0224(m); err != nil {
		return err
	}
	if len(f.SHA256) != 64 || f.Size < 0 || f.Size > 1<<32 {
		return errors.New("Некорректное значение: «хеш или размер файла»")
	}
	return nil
}

// Объекты рабочего пространства шифруются до передачи в хранилище Local/S3/CDN.
// Это предотвращает утечку исходников при открытой конфигурации хранилища до
// публикации. Ключ доменно отделён от Ed25519 seed подписи манифеста, а AEAD
// связывает проект, рабочее пространство и хеш содержимого.
func (s Server) workspaceCipher0226() (cipher.AEAD, error) {
	key, err := s.manifestSigningPrivateKey()
	if err != nil {
		return nil, err
	}
	seed := key.Seed()
	material := sha256.Sum256(append([]byte("Launcher build workspace encryption v1\x00"), seed...))
	block, err := aes.NewCipher(material[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func (s Server) encryptWorkspace0226(ws repository.BuildWorkspace, f repository.BuildFile, plain []byte) ([]byte, error) {
	aead, err := s.workspaceCipher0226()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	aad := []byte(ws.ProjectID + "\x00" + ws.ID + "\x00" + f.SHA256)
	sealed := aead.Seal(nil, nonce, plain, aad)
	return append(append([]byte("NLBW1"), nonce...), sealed...), nil
}
func (s Server) readWorkspaceSource0226(ws repository.BuildWorkspace, f repository.BuildFile) ([]byte, error) {
	src, size, err := s.Storage.Open(ws.ProjectID, ws.ID, workspaceObjectPath0226(f))
	if err != nil {
		return nil, err
	}
	defer src.Close()
	aead, err := s.workspaceCipher0226()
	if err != nil {
		return nil, err
	}
	max := f.Size + int64(len("NLBW1")) + int64(aead.NonceSize()+aead.Overhead())
	if size != max {
		return nil, fmt.Errorf("Несовпадение размера зашифрованных данных по пути %s", f.Path)
	}
	raw, err := io.ReadAll(io.LimitReader(src, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != max || !bytes.HasPrefix(raw, []byte("NLBW1")) {
		return nil, errors.New("Некорректное значение: «исходный бинарный объект»")
	}
	offset := len("NLBW1")
	nonce := raw[offset : offset+aead.NonceSize()]
	aad := []byte(ws.ProjectID + "\x00" + ws.ID + "\x00" + f.SHA256)
	plain, err := aead.Open(nil, nonce, raw[offset+aead.NonceSize():], aad)
	if err != nil {
		return nil, fmt.Errorf("Ошибка проверки подлинности источника по пути %s: %w", f.Path, err)
	}
	sum := sha256.Sum256(plain)
	if int64(len(plain)) != f.Size || hex.EncodeToString(sum[:]) != f.SHA256 {
		return nil, fmt.Errorf("Нарушена целостность источника по пути %s", f.Path)
	}
	return plain, nil
}
func (s Server) workspaceUpload0226(w http.ResponseWriter, r *http.Request) {
	store, ws, ok := s.ownedWorkspace0226(w, r, "file:write")
	if !ok {
		return
	}
	unlock, err := s.lockPackageMutation(r.Context(), "build-workspace:"+ws.ID)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	defer unlock()
	ws, err = store.GetBuildWorkspace(r.Context(), ws.ID)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if ws.State == "built" || ws.PackageID != "" {
		writeError(w, 409, "Рабочая область закреплена за релизным пакетом; исходные файлы и подготовленное содержимое нельзя менять")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.maxUploadBytes()+4096)
	if err = r.ParseMultipartForm(s.maxUploadBytes()); err != nil {
		writeError(w, 400, "Некорректный multipart-запрос или слишком большой файл")
		return
	}
	var expected int64
	if _, err = fmt.Sscan(r.FormValue("revision"), &expected); err != nil || expected != ws.Revision {
		writeError(w, 409, "Конфликт ревизий рабочего пространства")
		return
	}
	src, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, 400, "Требуется файловая часть запроса")
		return
	}
	defer src.Close()
	file := repository.BuildFile{Path: strings.TrimSpace(r.FormValue("path")), Ownership: strings.TrimSpace(r.FormValue("ownership")), Selected: true}
	if file.Path == "" {
		file.Path = header.Filename
	}
	if file.Ownership == "" {
		file.Ownership = "required"
	}
	file.Executable, file.TargetOS, err = releaseFileMetadata(r)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if len(ws.Files) >= maxWorkspaceFiles0226 {
		writeError(w, 413, "Достигнут лимит файлов рабочей области")
		return
	}
	// Вычисляйте хеш фактических байтов; хеш браузера, если он передан, является
	// лишь заявлением.
	data, err := io.ReadAll(io.LimitReader(src, s.maxUploadBytes()+1))
	if err != nil || int64(len(data)) > s.maxUploadBytes() {
		writeError(w, 413, "Слишком большой файл")
		return
	}
	file.Size = int64(len(data))
	sum := sha256.Sum256(data)
	file.SHA256 = hex.EncodeToString(sum[:])
	if expectedSHA := r.FormValue("sha256"); expectedSHA != "" && !strings.EqualFold(expectedSHA, file.SHA256) {
		writeError(w, 400, "Контрольная сумма SHA-256 не совпадает")
		return
	}
	if err = normalizeBuildFile0226(file); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	for _, other := range ws.Files {
		if strings.EqualFold(other.Path, file.Path) && other.Path != file.Path {
			writeError(w, 409, "Конфликт путей при сравнении без учёта регистра")
			return
		}
	}
	encrypted, encryptionErr := s.encryptWorkspace0226(ws, file, data)
	if encryptionErr != nil {
		writeError(w, 503, "Не удалось зашифровать рабочую область: "+encryptionErr.Error())
		return
	}
	if _, _, err = s.Storage.Save(ws.ProjectID, ws.ID, workspaceObjectPath0226(file), bytes.NewReader(encrypted)); err != nil {
		writeError(w, 503, "Не удалось записать в хранилище: "+err.Error())
		return
	}
	replaced := false
	for i, old := range ws.Files {
		if old.Path == file.Path {
			ws.Files[i] = file
			replaced = true
			break
		}
	}
	if !replaced {
		ws.Files = append(ws.Files, file)
	}
	sort.Slice(ws.Files, func(i, j int) bool { return ws.Files[i].Path < ws.Files[j].Path })
	ws.State = "importing"
	ws.BuildDigest = ""
	saved, err := store.SaveBuildWorkspace(r.Context(), ws)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	s.audit(r, ws.OwnerID, "build-workspace:import", ws.ID+":"+file.Path)
	writeJSON(w, 201, map[string]any{"apiVersion": apiContractVersion, "data": saved})
}

// workspaceRemoveFile0384 удаляет ошибочно импортированный логический файл до
// создания пакета. Зашифрованный объект с адресацией по хешу сохраняется для
// отложенной очистки: другой путь может иметь тот же хеш. Ревизия рабочего
// пространства не позволяет устаревшей вкладке удалить более новый ввод.
func (s Server) workspaceRemoveFile0384(w http.ResponseWriter, r *http.Request) {
	store, ws, ok := s.ownedWorkspace0226(w, r, "file:write")
	if !ok {
		return
	}
	unlock, err := s.lockPackageMutation(r.Context(), "build-workspace:"+ws.ID)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	defer unlock()
	ws, err = store.GetBuildWorkspace(r.Context(), ws.ID)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if ws.State == "built" || ws.PackageID != "" {
		writeError(w, 409, "Рабочая область закреплена за релизным пакетом; исходные файлы и подготовленное содержимое нельзя менять")
		return
	}
	var req struct {
		Revision int64  `json:"revision"`
		Path     string `json:"path"`
	}
	if err = readJSON0226(w, r, 4096, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if req.Revision != ws.Revision {
		writeError(w, 409, "Конфликт ревизий рабочего пространства")
		return
	}
	index := -1
	for i, f := range ws.Files {
		if f.Path == req.Path {
			index = i
			break
		}
	}
	if index < 0 {
		writeError(w, 404, "Файл рабочей области не найден")
		return
	}
	ws.Files = append(ws.Files[:index], ws.Files[index+1:]...)
	ws.State = "importing"
	ws.BuildDigest = ""
	saved, err := store.SaveBuildWorkspace(r.Context(), ws)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	s.audit(r, ws.OwnerID, "build-workspace:remove", ws.ID+":"+req.Path)
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": saved})
}

func (s Server) workspaceVerifyFile0226(ws repository.BuildWorkspace, file repository.BuildFile) error {
	_, err := s.readWorkspaceSource0226(ws, file)
	return err
}
func selectedFiles0226(ws repository.BuildWorkspace) []repository.BuildFile {
	out := []repository.BuildFile{}
	for _, f := range ws.Files {
		if f.Selected {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
func (s Server) workspaceScan0226(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := s.ownedWorkspace0226(w, r, "release:prepare")
	if !ok {
		return
	}
	checks := make([]map[string]any, 0, len(ws.Files))
	allOK := true
	for _, f := range ws.Files {
		err := s.workspaceVerifyFile0226(ws, f)
		status := "ok"
		if err != nil {
			status = "failed"
			allOK = false
		}
		checks = append(checks, map[string]any{"path": f.Path, "sha256": f.SHA256, "size": f.Size, "status": status})
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"revision": ws.Revision, "status": map[bool]string{true: "passed", false: "failed"}[allOK], "files": checks}})
}
func (s Server) workspaceDiff0226(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := s.ownedWorkspace0226(w, r, "release:prepare")
	if !ok {
		return
	}
	baseID := r.URL.Query().Get("baseVersionId")
	old := map[string]model.FileObject{}
	if baseID != "" {
		versions, err := s.Repo.ListVersions(ws.ProjectID)
		if err != nil {
			writeError(w, 503, err.Error())
			return
		}
		found := false
		for _, v := range versions {
			if v.ID == baseID && v.ProfileID == ws.ProfileID && v.Status == "published" {
				found = true
				break
			}
		}
		if !found {
			writeError(w, 400, "Базовая версия не опубликована в этом профиле")
			return
		}
		files, err := s.Repo.ListFiles(ws.ProjectID, baseID)
		if err != nil {
			writeError(w, 503, err.Error())
			return
		}
		for _, f := range files {
			old[f.Path] = f
		}
	}
	type row struct {
		Path   string `json:"path"`
		Change string `json:"change"`
		OldSHA string `json:"oldSha256,omitempty"`
		NewSHA string `json:"newSha256,omitempty"`
	}
	diff := []row{}
	for _, f := range selectedFiles0226(ws) {
		oldFile, had := old[f.Path]
		change := "added"
		if had {
			if oldFile.SHA256 == f.SHA256 {
				change = "unchanged"
			} else {
				change = "modified"
			}
			delete(old, f.Path)
		}
		diff = append(diff, row{f.Path, change, oldFile.SHA256, f.SHA256})
	}
	for _, f := range old {
		diff = append(diff, row{Path: f.Path, Change: "removed-from-package", OldSHA: f.SHA256})
	}
	sort.Slice(diff, func(i, j int) bool { return diff[i].Path < diff[j].Path })
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"items": diff, "revision": ws.Revision}})
}
func (s Server) workspaceStage0226(w http.ResponseWriter, r *http.Request) {
	store, ws, ok := s.ownedWorkspace0226(w, r, "release:prepare")
	if !ok {
		return
	}
	unlock, err := s.lockPackageMutation(r.Context(), "build-workspace:"+ws.ID)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	defer unlock()
	ws, err = store.GetBuildWorkspace(r.Context(), ws.ID)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if ws.State == "built" || ws.PackageID != "" {
		writeError(w, 409, "Рабочая область закреплена за релизным пакетом; исходные файлы и подготовленное содержимое нельзя менять")
		return
	}
	var req struct {
		Revision int64    `json:"revision"`
		Paths    []string `json:"paths"`
	}
	if err := readJSON0226(w, r, 1<<20, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if ws.Revision != req.Revision {
		writeError(w, 409, "Конфликт ревизий рабочего пространства")
		return
	}
	selected := map[string]bool{}
	for _, p := range req.Paths {
		if selected[p] {
			writeError(w, 400, "Повторяющийся путь в подготовленных файлах")
			return
		}
		selected[p] = true
	}
	count := 0
	for i := range ws.Files {
		_, ws.Files[i].Selected = selected[ws.Files[i].Path]
		if ws.Files[i].Selected {
			count++
			delete(selected, ws.Files[i].Path)
		}
	}
	if len(selected) != 0 || count == 0 {
		writeError(w, 400, "Для подготовки выберите существующие непустые файлы")
		return
	}
	ws.State = "staged"
	ws.BuildDigest = ""
	saved, err := store.SaveBuildWorkspace(r.Context(), ws)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	s.audit(r, ws.OwnerID, "build-workspace:stage", ws.ID)
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": saved})
}

// buildDigest стабилен между серверами, часовыми поясами, порядком обхода map и
// порядком передачи. Настройки Runtime и версии инструментов входят в идентичность
// входных данных.
func buildDigest0226(ws repository.BuildWorkspace) (string, error) {
	basis := struct {
		Schema          string                   `json:"schema"`
		ProjectID       string                   `json:"projectId"`
		ProfileID       string                   `json:"profileId"`
		ProfileDigest   string                   `json:"profileDigest"`
		ProfileRevision int64                    `json:"profileRevision"`
		Channel         string                   `json:"channel"`
		Version         string                   `json:"version"`
		Settings        repository.BuildSettings `json:"settings"`
		Files           []repository.BuildFile   `json:"files"`
	}{"build-workspace-v1", ws.ProjectID, ws.ProfileID, ws.ProfileDigest, ws.ProfileRevision, ws.Channel, ws.Version, ws.Settings, selectedFiles0226(ws)}
	b, err := json.Marshal(basis)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
func (s Server) workspaceValidate0226(ws repository.BuildWorkspace) (string, error) {
	if ws.State != "staged" && ws.State != "built" {
		return "", errors.New("Перед проверкой необходимо подготовить файлы")
	}
	files := selectedFiles0226(ws)
	if len(files) == 0 {
		return "", errors.New("Нет подготовленных файлов")
	}
	snapshot, err := repository.ReadProfileSnapshot(s.Repo, ws.ProjectID, ws.ProfileID)
	if err != nil {
		return "", err
	}
	if snapshot.Digest != ws.ProfileDigest || snapshot.Revision != ws.ProfileRevision {
		return "", errors.New("Ревизия профиля изменилась; создайте новую рабочую область")
	}
	manifests := make([]model.ManifestFile, 0, len(files))
	for _, f := range files {
		if err = normalizeBuildFile0226(f); err != nil {
			return "", err
		}
		if err = s.workspaceVerifyFile0226(ws, f); err != nil {
			return "", err
		}
		manifests = append(manifests, model.ManifestFile{Path: f.Path, Size: f.Size, SHA256: f.SHA256, URL: s.deliveryURL(ws.ProjectID, "preview", f.Path), Required: f.Ownership != "optional", Ownership: f.Ownership, Executable: f.Executable, TargetOS: f.TargetOS})
	}
	manifest := model.Manifest{SchemaVersion: model.ManifestSchemaV2, ProjectID: ws.ProjectID, ProfileID: ws.ProfileID, ProfileSnapshot: &snapshot, Channel: ws.Channel, Version: ws.Version, Minecraft: ws.Settings.Minecraft, Runtime: ws.Settings.Runtime, Directories: ws.Settings.Directories, FileRules: ws.Settings.FileRules, Files: manifests}
	if err = validateCompatibilityManifest(manifest); err != nil {
		return "", err
	}
	return buildDigest0226(ws)
}
func (s Server) workspaceValidateHandler0226(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := s.ownedWorkspace0226(w, r, "release:prepare")
	if !ok {
		return
	}
	digest, err := s.workspaceValidate0226(ws)
	if err != nil {
		writeError(w, 409, "Проверка сборки завершилась ошибкой: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"valid": true, "buildDigest": digest, "fileCount": len(selectedFiles0226(ws)), "profileRevision": ws.ProfileRevision}})
}
func (s Server) workspaceBuild0226(w http.ResponseWriter, r *http.Request) {
	store, ws, ok := s.ownedWorkspace0226(w, r, "release:prepare")
	if !ok {
		return
	}
	unlock, err := s.lockPackageMutation(r.Context(), "build-workspace:"+ws.ID)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	defer unlock()
	ws, err = store.GetBuildWorkspace(r.Context(), ws.ID)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if ws.State == "built" {
		writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": ws})
		return
	}
	var req struct {
		Revision int64 `json:"revision"`
	}
	if err = readJSON0226(w, r, 4096, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if ws.Revision != req.Revision {
		writeError(w, 409, "Конфликт ревизий рабочего пространства")
		return
	}
	digest, err := s.workspaceValidate0226(ws)
	if err != nil {
		writeError(w, 409, "Не удалось собрать: "+err.Error())
		return
	}
	// Зарезервируйте идентичность релиза ДО создания файлов. Блокировки рабочего
	// пространства и пакета защищают повторы и конкурирующие загрузки; чужой пакет
	// нельзя присвоить только из-за совпадения метаданных.
	packageID := ws.ProjectID + "-" + ws.ProfileID + "-" + ws.Version
	packageUnlock, err := s.lockPackageMutation(r.Context(), "package:"+packageID)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	defer packageUnlock()
	if ws.PackageID == "" {
		versions, lookupErr := s.Repo.ListVersions(ws.ProjectID)
		if lookupErr != nil {
			writeError(w, 503, "Не удалось проверить резервирование пакета: "+lookupErr.Error())
			return
		}
		for _, existing := range versions {
			if existing.ID == packageID || (existing.ProfileID == ws.ProfileID && existing.Channel == ws.Channel && existing.Version == ws.Version) {
				writeError(w, 409, "Версия уже относится к другой операции публикации релиза")
				return
			}
		}
		ws.PackageID = packageID
		ws, err = store.SaveBuildWorkspace(r.Context(), ws)
		if err != nil {
			writeError(w, 409, err.Error())
			return
		}
	}
	if ws.PackageID != packageID {
		writeError(w, 409, "Рабочая область привязана к другому пакету")
		return
	}
	release, err := s.Repo.CreateVersion(ws.ProjectID, ws.ProfileID, ws.Channel, ws.Version)
	if errors.Is(err, repository.ErrConflict) {
		versions, lookupErr := s.Repo.ListVersions(ws.ProjectID)
		if lookupErr != nil {
			writeError(w, 503, lookupErr.Error())
			return
		}
		found := false
		for _, candidate := range versions {
			if candidate.ID == packageID {
				release = candidate
				found = true
				break
			}
		}
		if !found {
			writeError(w, 409, "Версия существует, но недоступна")
			return
		}
		if release.ProjectID != ws.ProjectID || release.ProfileID != ws.ProfileID || release.Channel != ws.Channel || release.Version != ws.Version || release.Status != "draft" || release.Manifest.ProfileSnapshot == nil || release.Manifest.ProfileSnapshot.Digest != ws.ProfileDigest || release.Manifest.ProfileSnapshot.Revision != ws.ProfileRevision {
			writeError(w, 409, "Существующая версия не совпадает с закреплённой рабочей областью")
			return
		}
	} else if err != nil {
		writeError(w, 409, "Создание пакета: "+err.Error())
		return
	}
	if release.Manifest.ProfileSnapshot == nil || release.Manifest.ProfileSnapshot.Digest != ws.ProfileDigest || release.Manifest.ProfileSnapshot.Revision != ws.ProfileRevision {
		writeError(w, 409, "Снимок релиза отличается от рабочей области сборки; создать пакет невозможно")
		return
	}
	oldFiles, err := s.Repo.ListFiles(ws.ProjectID, release.ID)
	if err != nil {
		writeError(w, 503, err.Error())
		return
	}
	oldByPath := map[string]model.FileObject{}
	for _, f := range oldFiles {
		oldByPath[f.Path] = f
	}
	selected := selectedFiles0226(ws)
	if len(oldFiles) > len(selected) {
		writeError(w, 409, "Пакет уже содержит внешние файлы")
		return
	}
	for _, f := range oldFiles {
		found := false
		for _, candidate := range selected {
			if candidate.Path == f.Path && candidate.SHA256 == f.SHA256 && candidate.Size == f.Size && candidate.Ownership == f.Ownership {
				found = true
				break
			}
		}
		if !found {
			writeError(w, 409, "Пакет содержит посторонние или изменённые файлы")
			return
		}
	}
	for _, f := range selected {
		if _, ok := oldByPath[f.Path]; ok {
			continue
		}
		// Каждый источник повторно проверяется по AEAD и SHA-256 до копирования.
		data, e := s.readWorkspaceSource0226(ws, f)
		if e != nil {
			writeError(w, 409, "Содержимое источника изменилось: "+e.Error())
			return
		}
		if e = s.beforeStorageWrite0206(r, ws.ProjectID, release.ID, f.Path); e != nil {
			writeError(w, 409, e.Error())
			return
		}
		_, n, e := s.Storage.Save(ws.ProjectID, release.ID, f.Path, bytes.NewReader(data))
		if e != nil || n != f.Size {
			writeError(w, 503, "Не удалось сохранить собранный файл")
			return
		}
		object := model.FileObject{ProjectID: ws.ProjectID, VersionID: release.ID, Path: f.Path, Size: f.Size, SHA256: f.SHA256, URL: s.deliveryURL(ws.ProjectID, release.ID, f.Path), Required: f.Ownership != "optional", Ownership: f.Ownership, Executable: f.Executable, TargetOS: f.TargetOS}
		savedObject, addErr := s.Repo.AddFile(object)
		if addErr != nil {
			writeError(w, 503, "Не удалось индексировать собранный файл: "+addErr.Error())
			return
		}
		s.storageWritten0206(r, savedObject)
	}
	manifest := release.Manifest
	manifest.Minecraft = ws.Settings.Minecraft
	manifest.Runtime = ws.Settings.Runtime
	manifest.Directories = ws.Settings.Directories
	manifest.FileRules = ws.Settings.FileRules
	manifest.Signature = nil
	// Снимком профиля управляет CreateVersion; здесь он никогда не
	// перезаписывается.
	if e := model.ValidateManifestSchema(manifest); e != nil {
		writeError(w, 409, e.Error())
		return
	}
	if _, e = s.Repo.UpdateVersionManifest(ws.ProjectID, release.ID, manifest); e != nil {
		writeError(w, 409, "Не удалось сохранить манифест: "+e.Error())
		return
	}
	ws.State = "built"
	ws.PackageID = release.ID
	ws.BuildDigest = digest
	saved, err := store.SaveBuildWorkspace(r.Context(), ws)
	if err != nil {
		writeError(w, 409, "Не удалось сохранить рабочую область; повторите сборку: "+err.Error())
		return
	}
	s.audit(r, ws.OwnerID, "build-workspace:build", ws.ID+":"+digest)
	writeJSON(w, 201, map[string]any{"apiVersion": apiContractVersion, "data": saved})
}
