// Package launcherapi предоставляет промышленный HTTP-клиент канонического Launcher OpenAPI v1.
package launcherapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const ContractVersion = "1.0.0"
const maxResponseBytes = 8 << 20

type Operation struct{ Method, Path string }
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}
type APIError struct {
	Status                   int
	Code, Message, RequestID string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API Launcher: статус=%d, код=%q, идентификатор запроса=%q: %s", e.Status, e.Code, e.RequestID, e.Message)
}

// httpStatusRu используется только при отсутствии сообщения сервера.
func httpStatusRu(status int) string {
	var explanation string
	switch status {
	case 300:
		explanation = "Выбор из нескольких вариантов"
	case 301:
		explanation = "Ресурс перемещён"
	case 302:
		explanation = "Ресурс временно перемещён"
	case 303:
		explanation = "См. другой ресурс"
	case 304:
		explanation = "Ресурс не изменился"
	case 307:
		explanation = "Временное перенаправление"
	case 308:
		explanation = "Постоянное перенаправление"
	case 400:
		explanation = "Некорректный запрос"
	case 401:
		explanation = "Требуется авторизация"
	case 403:
		explanation = "Доступ запрещён"
	case 404:
		explanation = "Не найдено"
	case 405:
		explanation = "Метод запроса не разрешён"
	case 406:
		explanation = "Нет подходящего формата ответа"
	case 408:
		explanation = "Время ожидания запроса истекло"
	case 409:
		explanation = "Конфликт данных"
	case 410:
		explanation = "Ресурс больше недоступен"
	case 413:
		explanation = "Слишком большой запрос"
	case 415:
		explanation = "Неподдерживаемый формат данных"
	case 422:
		explanation = "Не удалось обработать запрос"
	case 423:
		explanation = "Ресурс заблокирован"
	case 429:
		explanation = "Слишком много запросов"
	case 500:
		explanation = "Внутренняя ошибка сервера"
	case 501:
		explanation = "Операция не поддерживается сервером"
	case 502:
		explanation = "Ошибка шлюза"
	case 503:
		explanation = "Сервис временно недоступен"
	case 504:
		explanation = "Время ответа сервера истекло"
	default:
		explanation = "Ошибка запроса к серверу"
	}
	return fmt.Sprintf("HTTP %d: %s", status, explanation)
}

var segment = regexp.MustCompile(`\{([^{}]+)\}`)

func New(baseURL, token string) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u == nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return nil, errors.New("Некорректный базовый URL API")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if u.Scheme != "https" && !(u.Scheme == "http" && (strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback())) {
		return nil, errors.New("Для API требуется HTTPS (HTTP разрешён только для петлевого интерфейса)")
	}
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), Token: token, HTTP: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func Path(template string, params map[string]string) (string, error) {
	if !strings.HasPrefix(template, "/") || strings.Contains(template, "?") || strings.Contains(template, "#") {
		return "", errors.New("Некорректный шаблон маршрута")
	}
	used := map[string]bool{}
	var resolveErr error
	resolved := segment.ReplaceAllStringFunc(template, func(match string) string {
		key := match[1 : len(match)-1]
		v, ok := params[key]
		used[key] = true
		if !ok || v == "" || v == "." || v == ".." || strings.ContainsAny(v, "/\\") {
			resolveErr = fmt.Errorf("Недопустимый параметр пути %s", key)
			return ""
		}
		return url.PathEscape(v)
	})
	if resolveErr != nil {
		return "", resolveErr
	}
	for k := range params {
		if !used[k] {
			return "", fmt.Errorf("Неожиданный параметр пути %s", k)
		}
	}
	if strings.Contains(resolved, "{") || strings.Contains(resolved, "}") {
		return "", errors.New("Не подставлено значение параметра маршрута")
	}
	return resolved, nil
}
func (c *Client) Call(ctx context.Context, operationID string, params map[string]string, query url.Values, request any, response any, idempotencyKey string) error {
	op, ok := Operations[operationID]
	if !ok {
		return fmt.Errorf("Неизвестное значение: OpenAPI операция: %s", operationID)
	}
	path, err := Path(op.Path, params)
	if err != nil {
		return err
	}
	return c.Request(ctx, op.Method, path, query, request, response, idempotencyKey)
}
func (c *Client) Request(ctx context.Context, method, path string, query url.Values, request any, response any, key string) error {
	if c == nil || c.HTTP == nil {
		return errors.New("Клиент не инициализирован")
	}
	if !strings.HasPrefix(path, "/api/v1/") && path != "/health" && path != "/ready" && path != "/metrics" && !strings.HasPrefix(path, "/api/profiles/minecraft") && !strings.HasPrefix(path, "/api/user/profile/") && !strings.HasPrefix(path, "/authserver/") && !strings.HasPrefix(path, "/sessionserver/") {
		return errors.New("Маршрут не входит в поддерживаемый OpenAPI версии 1")
	}
	if strings.Contains(path, "?") || strings.Contains(path, "#") || strings.Contains(path, "..") || strings.HasPrefix(path, "//") {
		return errors.New("Небезопасный путь запроса")
	}
	var body io.Reader
	if request != nil {
		encoded, err := json.Marshal(request)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	u := c.BaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if request != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if key != "" {
		if strings.ContainsAny(key, "\r\n") {
			return errors.New("Недопустимый ключ идемпотентности")
		}
		req.Header.Set("Idempotency-Key", key)
	}
	result, err := c.doNoRedirect(req)
	if err != nil {
		return err
	}
	defer result.Body.Close()
	data, err := io.ReadAll(io.LimitReader(result.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxResponseBytes {
		return errors.New("Размер ответа API превышает 8 МиБ")
	}
	if result.StatusCode < 200 || result.StatusCode > 299 {
		var e struct {
			Code    string `json:"code"`
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &e)
		msg := e.Message
		if msg == "" {
			msg = e.Error
		}
		if msg == "" {
			msg = httpStatusRu(result.StatusCode)
		}
		return &APIError{Status: result.StatusCode, Code: e.Code, Message: msg, RequestID: result.Header.Get("X-Correlation-ID")}
	}
	if response != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, response); err != nil {
			return fmt.Errorf("Ошибка декодирования ответа API: %w", err)
		}
	}
	return nil
}

// CheckCompatibility принимает текущий контракт API v1 и установленного предшественника
// 0.45.11. Старые backend не публиковали X-Launcher-API-Contract, поэтому проверяется версия
// через /ready.
func (c *Client) CheckCompatibility(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/ready", nil)
	if err != nil {
		return err
	}
	resp, err := c.doNoRedirect(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("Серверная часть ещё не готова: %d", resp.StatusCode)
	}
	contract := resp.Header.Get("X-Launcher-API-Contract")
	if contract != "" {
		if contract != ContractVersion {
			return fmt.Errorf("Несовместимый контракт API: %q", contract)
		}
		return nil
	}
	var info struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&info); err != nil {
		return err
	}
	if info.Version != "0.45.11" && info.Version != "0.45.12" {
		return fmt.Errorf("Совместимость серверной части %q с v1 не подтверждена", info.Version)
	}
	return nil
}

// CallRaw отправляет multipart/бинарные данные в любую зарегистрированную операцию
// OpenAPI. Для JSON используйте Call; необработанные ответы возвращаются байтами, без
// искажающего преобразования в JSON.
func (c *Client) CallRaw(ctx context.Context, operationID string, params map[string]string, query url.Values, body []byte, contentType, idempotencyKey string) ([]byte, error) {
	op, ok := Operations[operationID]
	if !ok {
		return nil, fmt.Errorf("Неизвестное значение: OpenAPI операция: %s", operationID)
	}
	path, err := Path(op.Path, params)
	if err != nil {
		return nil, err
	}
	if c == nil || c.HTTP == nil {
		return nil, errors.New("Клиент не инициализирован")
	}
	if idempotencyKey != "" && strings.ContainsAny(idempotencyKey, "\r\n") {
		return nil, errors.New("Недопустимый ключ идемпотентности")
	}
	target := c.BaseURL + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, op.Method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	resp, err := c.doNoRedirect(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxResponseBytes {
		return nil, errors.New("Размер ответа API превышает 8 МиБ")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Error   string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		message := e.Message
		if message == "" {
			message = e.Error
		}
		if message == "" {
			message = httpStatusRu(resp.StatusCode)
		}
		return nil, &APIError{Status: resp.StatusCode, Code: e.Code, Message: message, RequestID: resp.Header.Get("X-Correlation-ID")}
	}
	return data, nil
}

// CallStream передаёт запрос и ответ операции OpenAPI без буферизации успешного
// ответа. Для multipart допускается потоковый io.Reader; вызывающая сторона
// отвечает за requestReader и responseWriter. Нулевой предел ответа означает
// стандартные 1 ГиБ. При ошибке вызывающая сторона должна удалить частично
// записанный файл назначения.
func (c *Client) CallStream(ctx context.Context, operationID string, params map[string]string, query url.Values, requestReader io.Reader, contentType string, responseWriter io.Writer, maxResponseBytes int64, idempotencyKey string) (int64, error) {
	op, ok := Operations[operationID]
	if !ok {
		return 0, fmt.Errorf("Неизвестное значение: OpenAPI операция: %s", operationID)
	}
	path, err := Path(op.Path, params)
	if err != nil {
		return 0, err
	}
	return c.RequestStream(ctx, op.Method, path, query, requestReader, contentType, responseWriter, maxResponseBytes, idempotencyKey)
}

// RequestStream предотвращает перенаправления на другой origin, даже если
// вызывающий код передал http.Client с разрешёнными редиректами. Сам клиент не
// изменяется.
func (c *Client) RequestStream(ctx context.Context, method, path string, query url.Values, requestReader io.Reader, contentType string, responseWriter io.Writer, maxResponseBytes int64, key string) (int64, error) {
	if c == nil || c.HTTP == nil {
		return 0, errors.New("Клиент не инициализирован")
	}
	if !strings.HasPrefix(path, "/api/v1/") && path != "/health" && path != "/ready" && path != "/metrics" && !strings.HasPrefix(path, "/api/profiles/minecraft") && !strings.HasPrefix(path, "/api/user/profile/") && !strings.HasPrefix(path, "/authserver/") && !strings.HasPrefix(path, "/sessionserver/") {
		return 0, errors.New("Маршрут не входит в поддерживаемый OpenAPI версии 1")
	}
	if strings.Contains(path, "?") || strings.Contains(path, "#") || strings.Contains(path, "..") || strings.HasPrefix(path, "//") {
		return 0, errors.New("Небезопасный путь запроса")
	}
	if key != "" && strings.ContainsAny(key, "\r\n") {
		return 0, errors.New("Недопустимый ключ идемпотентности")
	}
	if maxResponseBytes == 0 {
		maxResponseBytes = 1 << 30
	}
	if maxResponseBytes < 0 || maxResponseBytes > 1<<30 {
		return 0, errors.New("Недопустимый лимит ответа (не более 1 ГиБ)")
	}
	if responseWriter == nil {
		return 0, errors.New("Необходим обработчик записи ответа")
	}
	target := c.BaseURL + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, requestReader)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "*/*")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	resp, err := c.doNoRedirect(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Не раскрывайте токен авторизации адресату редиректа и не разбирайте
		// неограниченные ответы об ошибках под контролем атакующего.
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytesForError+1))
		if err != nil {
			return 0, err
		}
		if len(data) > maxResponseBytesForError {
			return 0, errors.New("Ответ API с ошибкой слишком большой")
		}
		var parsed struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Error   string `json:"error"`
		}
		_ = json.Unmarshal(data, &parsed)
		message := parsed.Message
		if message == "" {
			message = parsed.Error
		}
		if message == "" {
			message = httpStatusRu(resp.StatusCode)
		}
		return 0, &APIError{Status: resp.StatusCode, Code: parsed.Code, Message: message, RequestID: resp.Header.Get("X-Correlation-ID")}
	}
	if resp.ContentLength > maxResponseBytes {
		return 0, errors.New("Поток API превышает настроенное ограничение размера")
	}
	// LimitReader(max+1) выявляет chunked-ответ больше объявленного предела;
	// полный ответ не выделяется в память.
	n, err := io.Copy(responseWriter, io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return n, err
	}
	if n > maxResponseBytes {
		return n, errors.New("Поток API превышает настроенное ограничение размера")
	}
	return n, nil
}

const maxResponseBytesForError = 1 << 20

// doNoRedirect защищает Bearer-учётные данные и не позволяет принять перенаправление
// на другой origin за ответ API. Клиент, предоставленный вызывающим кодом, не может
// это отменить.
func (c *Client) doNoRedirect(req *http.Request) (*http.Response, error) {
	client := *c.HTTP
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client.Do(req)
}
