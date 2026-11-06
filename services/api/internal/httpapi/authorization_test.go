package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func loginUser0211(t *testing.T, handler http.Handler, email, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/login", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("login %s returned %d: %s", email, res.Code, res.Body.String())
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil || payload.Token == "" {
		t.Fatalf("Вход %s не вернул токен: ошибка=%v ответ=%s", email, err, res.Body.String())
	}
	return payload.Token
}

func request0211(t *testing.T, handler http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}

func TestProjectAuthorization0211IsScopedAndLive(t *testing.T) {
	handler := testServer(t)
	admin := loginAdmin(t, handler)

	res := request0211(t, handler, http.MethodPost, "/api/v1/admin/projects", admin,
		`{"id":"project-b","name":"Project B","defaultChannel":"stable"}`)
	if res.Code != http.StatusCreated {
		t.Fatalf("Создание project-b вернуло %d: %s", res.Code, res.Body.String())
	}

	admin, _ = registerTestPasskey117(t, handler, admin)
	res = request0211(t, handler, http.MethodPost, "/api/v1/admin/users", admin,
		`{"email":"operator0211@example.test","displayName":"Scoped Operator","roleId":"player","password":"operator-password-0211","projectRoles":{"demo-project":"operator"}}`)
	if res.Code != http.StatusCreated {
		t.Fatalf("Создание оператора с ограниченными правами вернуло %d: %s", res.Code, res.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("Не удалось декодировать оператора с ограниченными правами: ошибка=%v ответ=%s", err, res.Body.String())
	}

	operator := loginUser0211(t, handler, "operator0211@example.test", "operator-password-0211")

	// Конкретное членство в проекте разрешает доступ к этому проекту.
	res = request0211(t, handler, http.MethodPatch, "/api/v1/admin/projects/demo-project", operator, `{"description":"authorized-0211"}`)
	if res.Code != http.StatusOK {
		t.Fatalf("Изменение собственного проекта вернуло %d: %s", res.Code, res.Body.String())
	}

	// Та же роль не распространяется на другие проекты.
	res = request0211(t, handler, http.MethodPatch, "/api/v1/admin/projects/project-b", operator, `{"description":"must-not-change"}`)
	if res.Code != http.StatusForbidden {
		t.Fatalf("Изменение чужого проекта вернуло %d, ожидается 403: %s", res.Code, res.Body.String())
	}

	// Конечные точки, область которых задаёт тело запроса, проверяются после извлечения projectId.
	res = request0211(t, handler, http.MethodPost, "/api/v1/packages", operator,
		`{"projectId":"project-b","profileId":"vanilla","channel":"stable","version":"0.21.1-cross-project"}`)
	if res.Code != http.StatusForbidden {
		t.Fatalf("Создание пакета чужого проекта вернуло %d, ожидается 403: %s", res.Code, res.Body.String())
	}
	res = request0211(t, handler, http.MethodPost, "/api/v1/telemetry/events", operator,
		`{"projectId":"project-b","event":"forbidden"}`)
	if res.Code != http.StatusForbidden {
		t.Fatalf("Телеметрия чужого проекта вернула %d, ожидается 403: %s", res.Code, res.Body.String())
	}

	// Резервные копии экземпляра не являются правом отдельного проекта.
	res = request0211(t, handler, http.MethodPost, "/api/v1/operations/backups", operator, `{}`)
	if res.Code != http.StatusForbidden {
		t.Fatalf("Оператор проекта получил доступ к резервной копии экземпляра: статус=%d ответ=%s", res.Code, res.Body.String())
	}

	// Отзыв членства действует и на ранее выданный токен. Управление
	// пользователями само по себе требует свежий устойчивый к фишингу сеанс.
	res = request0211(t, handler, http.MethodPatch, "/api/v1/admin/users/"+created.ID, admin,
		`{"projectRoles":{}}`)
	if res.Code != http.StatusOK {
		t.Fatalf("Отзыв членства вернул %d: %s", res.Code, res.Body.String())
	}
	res = request0211(t, handler, http.MethodPatch, "/api/v1/admin/projects/demo-project", operator, `{"description":"revoked"}`)
	if res.Code != http.StatusForbidden {
		t.Fatalf("Отозванный токен продолжил изменять проект: статус=%d ответ=%s", res.Code, res.Body.String())
	}
}

func TestGlobalRoleRevocation0211AppliesToExistingToken(t *testing.T) {
	handler := testServer(t)
	admin := loginAdmin(t, handler)

	admin, _ = registerTestPasskey117(t, handler, admin)
	res := request0211(t, handler, http.MethodPost, "/api/v1/admin/users", admin,
		`{"email":"global0211@example.test","displayName":"Temporary Admin","roleId":"admin","password":"temporary-admin-0211","projectRoles":{}}`)
	if res.Code != http.StatusCreated {
		t.Fatalf("Создание временного администратора вернуло %d: %s", res.Code, res.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("Не удалось декодировать временного администратора: ошибка=%v ответ=%s", err, res.Body.String())
	}
	token := loginUser0211(t, handler, "global0211@example.test", "temporary-admin-0211")

	res = request0211(t, handler, http.MethodPost, "/api/v1/admin/projects", token, `{"id":"global-before-revoke","name":"Before"}`)
	if res.Code != http.StatusCreated {
		t.Fatalf("Проверка глобальных прав администратора до отзыва вернула %d: %s", res.Code, res.Body.String())
	}

	res = request0211(t, handler, http.MethodPatch, "/api/v1/admin/users/"+created.ID, admin, `{"roleId":"player"}`)
	if res.Code != http.StatusOK {
		t.Fatalf("Отзыв глобальной роли вернул %d: %s", res.Code, res.Body.String())
	}
	res = request0211(t, handler, http.MethodPost, "/api/v1/admin/projects", token, `{"id":"global-after-revoke","name":"After"}`)
	if res.Code != http.StatusForbidden {
		t.Fatalf("Устаревший токен администратора сохранил глобальное право project:write: статус=%d ответ=%s", res.Code, res.Body.String())
	}
}
