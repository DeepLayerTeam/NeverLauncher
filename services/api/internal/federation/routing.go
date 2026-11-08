package federation

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector"
)

var (
	ErrRoutingRequired = errors.New("Необходимо явно указать провайдера авторизации")
	ErrRoutingDenied   = errors.New("Провайдер авторизации запрещён политикой маршрутизации")
	ErrLinkingDisabled = errors.New("Для провайдера отключена привязка учётных записей")
)

// RoutingRule определяет единственного допустимого парольного провайдера для точного
// домена email. Строгие правила также отклоняют вручную переданные альтернативные
// провайдеры. Они никогда не повторяют учётные данные против другого Backend.
type RoutingRule struct {
	EmailDomain string `json:"emailDomain"`
	ProviderID  string `json:"providerId"`
	Strict      bool   `json:"strict,omitempty"`
}

type RoutingConfig struct {
	Version                 int           `json:"version"`
	DefaultProvider         string        `json:"defaultProvider,omitempty"`
	RequireExplicitProvider bool          `json:"requireExplicitProvider,omitempty"`
	Rules                   []RoutingRule `json:"rules,omitempty"`
	// Если указано, только этих провайдеров можно явно привязать к существующему
	// аутентифицированному аккаунту Never после нового подтверждения провайдером.
	LinkingAllowProviders []string `json:"linkingAllowProviders,omitempty"`
	DisableLinking        bool     `json:"disableLinking,omitempty"`
}

var validRouteDomain0293 = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$`)

// LoadRoutingConfig ограничивает размер конфигурации и отклоняет неизвестные поля и
// лишние JSON-объекты. Пустая конфигурация сохраняет локальное поведение 0.29.2.
func LoadRoutingConfig(jsonValue, filePath string) (RoutingConfig, error) {
	if strings.TrimSpace(jsonValue) != "" && strings.TrimSpace(filePath) != "" {
		return RoutingConfig{}, errors.New("Настройте только один из параметров: LAUNCHER_AUTH_ROUTING_JSON либо LAUNCHER_AUTH_ROUTING_FILE")
	}
	var raw []byte
	if strings.TrimSpace(filePath) != "" {
		file, err := os.Open(strings.TrimSpace(filePath))
		if err != nil {
			return RoutingConfig{}, fmt.Errorf("Открытие конфигурации маршрутизации авторизации: %w", err)
		}
		defer file.Close()
		raw, err = io.ReadAll(io.LimitReader(file, 65537))
		if err != nil {
			return RoutingConfig{}, err
		}
	} else {
		raw = []byte(strings.TrimSpace(jsonValue))
	}
	if len(raw) == 0 {
		return RoutingConfig{Version: 1, DefaultProvider: "local"}, nil
	}
	if len(raw) > 65536 {
		return RoutingConfig{}, errors.New("Конфигурация маршрутизации авторизации превышает 64 КиБ")
	}
	if err := rejectDuplicateRoutingKeys0293(json.NewDecoder(strings.NewReader(string(raw)))); err != nil {
		return RoutingConfig{}, fmt.Errorf("Неоднозначный JSON маршрутизации авторизации: %w", err)
	}
	var cfg RoutingConfig
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return RoutingConfig{}, fmt.Errorf("Декодирование маршрутизации авторизации: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return RoutingConfig{}, errors.New("Конфигурация маршрутизации авторизации должна содержать ровно один JSON-объект")
	}
	return cfg, nil
}

// rejectDuplicateRoutingKeys0293 рекурсивно проверяет каждый объект, включая
// вложенные правила. Повтор ключа не должен незаметно переопределять строгий
// маршрут.
func rejectDuplicateRoutingKeys0293(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delimiter, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			token, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return errors.New("Некорректное значение: объект JSON ключ")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("Обнаружен дубликат: ключ %q", key)
			}
			seen[key] = struct{}{}
			if err := rejectDuplicateRoutingKeys0293(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := rejectDuplicateRoutingKeys0293(dec); err != nil {
				return err
			}
		}
	default:
		return errors.New("Неожиданное значение: разделитель JSON")
	}
	_, err = dec.Token()
	return err
}

// ConfigureRouting проверяет всех провайдеров и атомарно устанавливает
// неизменяемые правила маршрутизации. Ошибочный или отсутствующий провайдер
// блокирует запуск API.
func (c *Core) ConfigureRouting(cfg RoutingConfig) error {
	if cfg.Version != 1 {
		return fmt.Errorf("Неподдерживаемая версия правил маршрутизации авторизации: %d", cfg.Version)
	}
	cfg.DefaultProvider = strings.ToLower(strings.TrimSpace(cfg.DefaultProvider))
	if cfg.DefaultProvider == "" && !cfg.RequireExplicitProvider {
		cfg.DefaultProvider = "local"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	eligible := func(id string) bool {
		conn, ok := c.connectors[id]
		return ok && authconnector.HasCapability(conn.Metadata(), authconnector.CapabilityPasswordAuth)
	}
	if cfg.DefaultProvider != "" && !eligible(cfg.DefaultProvider) {
		return fmt.Errorf("Провайдер авторизации по умолчанию %q отсутствует или недоступен; проверка паролей запрещена", cfg.DefaultProvider)
	}
	rules := make([]RoutingRule, 0, len(cfg.Rules))
	domains := make(map[string]struct{}, len(cfg.Rules))
	if len(cfg.Rules) > 256 {
		return errors.New("Маршрутизация авторизации превышает лимит в 256 правил")
	}
	for _, rule := range cfg.Rules {
		rule.EmailDomain = strings.ToLower(strings.TrimSpace(rule.EmailDomain))
		rule.ProviderID = strings.ToLower(strings.TrimSpace(rule.ProviderID))
		if len(rule.EmailDomain) > 253 || !validRouteDomain0293.MatchString(rule.EmailDomain) {
			return fmt.Errorf("Некорректный домен электронной почты в правилах авторизации: %q", rule.EmailDomain)
		}
		for _, label := range strings.Split(rule.EmailDomain, ".") {
			if len(label) > 63 {
				return fmt.Errorf("Некорректная часть доменного имени электронной почты: %q", rule.EmailDomain)
			}
		}
		if _, exists := domains[rule.EmailDomain]; exists {
			return fmt.Errorf("Повторяющийся домен в правилах авторизации: %q", rule.EmailDomain)
		}
		if !eligible(rule.ProviderID) {
			return fmt.Errorf("Провайдер авторизации %q отсутствует или недоступен; проверка паролей запрещена", rule.ProviderID)
		}
		domains[rule.EmailDomain] = struct{}{}
		rules = append(rules, rule)
	}
	if cfg.DisableLinking && len(cfg.LinkingAllowProviders) != 0 {
		return errors.New("Нельзя одновременно использовать параметры disableLinking и linkingAllowProviders")
	}
	if len(cfg.LinkingAllowProviders) > 256 {
		return errors.New("Список разрешённых привязок учётных записей превышает 256 записей")
	}
	linking := make([]string, 0, len(cfg.LinkingAllowProviders))
	seen := map[string]bool{}
	for _, id := range cfg.LinkingAllowProviders {
		id = strings.ToLower(strings.TrimSpace(id))
		if _, exists := c.connectors[id]; !exists {
			return fmt.Errorf("Провайдер привязки учётных записей %q не зарегистрирован", id)
		}
		if seen[id] {
			return fmt.Errorf("Повторяющийся провайдер привязки учётных записей: %q", id)
		}
		seen[id] = true
		linking = append(linking, id)
	}
	cfg.Rules, cfg.LinkingAllowProviders = rules, linking
	c.routing = cfg
	return nil
}

// Routing возвращает защищённую копию активной конфигурации Runtime.
func (c *Core) Routing() RoutingConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	cfg := c.routing
	cfg.Rules = append([]RoutingRule(nil), cfg.Rules...)
	cfg.LinkingAllowProviders = append([]string(nil), cfg.LinkingAllowProviders...)
	if cfg.Version == 0 {
		return RoutingConfig{Version: 1, DefaultProvider: "local"}
	}
	return cfg
}

func routeEmailDomain0293(identifier string) string {
	identifier = strings.TrimSpace(identifier)
	if strings.Count(identifier, "@") != 1 {
		return ""
	}
	at := strings.LastIndexByte(identifier, '@')
	if at < 1 {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(identifier[at+1:]), ".")
}

// RoutePasswordProvider выбирает провайдера один раз. Вызывающая сторона должна
// аутентифицировать только через возвращённый коннектор и передавать любую ошибку
// без изменений.
func (c *Core) RoutePasswordProvider(requested, identifier string) (string, error) {
	requested = strings.ToLower(strings.TrimSpace(requested))
	cfg := c.Routing()
	matched := RoutingRule{}
	domain := routeEmailDomain0293(identifier)
	for _, rule := range cfg.Rules {
		if rule.EmailDomain == domain {
			matched = rule
			break
		}
	}
	if requested == "" {
		if matched.ProviderID != "" {
			requested = matched.ProviderID
		} else if cfg.RequireExplicitProvider {
			return "", ErrRoutingRequired
		} else {
			requested = cfg.DefaultProvider
		}
	} else if matched.ProviderID != "" && matched.Strict && requested != matched.ProviderID {
		return "", ErrRoutingDenied
	}
	conn, exists := c.Connector(requested)
	if !exists {
		return "", ErrProviderNotFound
	}
	if !authconnector.HasCapability(conn.Metadata(), authconnector.CapabilityPasswordAuth) {
		return "", ErrCapabilityUnsupported
	}
	return requested, nil
}

// EnsureLinkAllowed применяет настроенный список разрешённых провайдеров для
// браузерной и парольной привязки, не используя непроверенные email-утверждения.
func (c *Core) EnsureLinkAllowed(providerID string) error {
	providerID = strings.ToLower(strings.TrimSpace(providerID))
	c.mu.RLock()
	_, exists := c.connectors[providerID]
	cfg := c.routing
	c.mu.RUnlock()
	if !exists {
		return ErrProviderNotFound
	}
	if cfg.DisableLinking {
		return ErrLinkingDisabled
	}
	if len(cfg.LinkingAllowProviders) == 0 {
		return nil
	}
	for _, allowed := range cfg.LinkingAllowProviders {
		if allowed == providerID {
			return nil
		}
	}
	return ErrLinkingDisabled
}
