// Пакет configmigration обрабатывает формат JSON со списком провайдеров.
// Устаревшие массивы провайдеров без версии обновляются в памяти при активации;
// исходный файл НЕ перезаписывается, а ссылки на секреты остаются нетронутыми.
package configmigration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const CurrentSchemaVersion = 2

type envelope struct {
	SchemaVersion int             `json:"schemaVersion"`
	Providers     json.RawMessage `json:"providers,omitempty"`
	Configs       json.RawMessage `json:"configs,omitempty"`
}

// Decode читает рабочий список настроенных провайдеров. Обновляет устаревшие массивы
// и конверты v1, отклоняя неизвестные версии схемы и неоднозначные
// конверты, вместо незаметного выбора другого списка провайдеров.
// Возвращаемая версия — действующая версия схемы, а не версия входных данных.
func Decode[T any](raw []byte) ([]T, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, errors.New("provider configuration is empty")
	}
	var entries json.RawMessage
	switch raw[0] {
	case '[': // Existing production format, version 1.
		entries = raw
	case '{':
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var e envelope
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("decode provider configuration envelope: %w", err)
		}
		var trailing any
		if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
			return nil, errors.New("trailing provider configuration data")
		}
		switch e.SchemaVersion {
		case 1:
			if len(e.Configs) == 0 || len(e.Providers) != 0 {
				return nil, errors.New("schema v1 must have configs only")
			}
			entries = e.Configs
		case CurrentSchemaVersion:
			if len(e.Providers) == 0 || len(e.Configs) != 0 {
				return nil, errors.New("schema v2 must have providers only")
			}
			entries = e.Providers
		default:
			return nil, fmt.Errorf("unsupported provider configuration schema version %d", e.SchemaVersion)
		}
	default:
		return nil, errors.New("provider configuration must be JSON array or versioned object")
	}
	if len(entries) == 0 || entries[0] != '[' {
		return nil, errors.New("provider configuration entries must be an array")
	}
	dec := json.NewDecoder(bytes.NewReader(entries))
	dec.DisallowUnknownFields()
	var configs []T
	if err := dec.Decode(&configs); err != nil {
		return nil, fmt.Errorf("decode configured providers: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing provider list data")
	}
	if len(configs) == 0 {
		return nil, errors.New("provider configuration contains no providers")
	}
	return configs, nil
}
