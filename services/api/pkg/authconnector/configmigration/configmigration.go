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
		return nil, errors.New("Конфигурация провайдера пуста")
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
			return nil, fmt.Errorf("Ошибка декодирования контейнера конфигурации провайдера: %w", err)
		}
		var trailing any
		if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
			return nil, errors.New("Лишние данные после конфигурации провайдера")
		}
		switch e.SchemaVersion {
		case 1:
			if len(e.Configs) == 0 || len(e.Providers) != 0 {
				return nil, errors.New("В схеме v1 допускается только поле configs")
			}
			entries = e.Configs
		case CurrentSchemaVersion:
			if len(e.Providers) == 0 || len(e.Configs) != 0 {
				return nil, errors.New("В схеме v2 допускается только поле providers")
			}
			entries = e.Providers
		default:
			return nil, fmt.Errorf("Неподдерживаемая версия схемы конфигурации провайдера: %d", e.SchemaVersion)
		}
	default:
		return nil, errors.New("Конфигурация провайдера должна быть массивом JSON или объектом с версией")
	}
	if len(entries) == 0 || entries[0] != '[' {
		return nil, errors.New("Записи конфигурации провайдера должны образовывать массив")
	}
	dec := json.NewDecoder(bytes.NewReader(entries))
	dec.DisallowUnknownFields()
	var configs []T
	if err := dec.Decode(&configs); err != nil {
		return nil, fmt.Errorf("Ошибка декодирования настроенных провайдеров: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("Лишние данные после списка провайдеров")
	}
	if len(configs) == 0 {
		return nil, errors.New("В конфигурации провайдера нет ни одного провайдера")
	}
	return configs, nil
}
