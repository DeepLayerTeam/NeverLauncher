package repository

import (
	"encoding/json"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Сохранение только первого из двух сцепленных JSON-документов незаметно изменит
// подписанную или впоследствии хешируемую полезную нагрузку события до устойчивой
// публикации.
func TestExtensionEventRejectsTrailingJSON0423(t *testing.T) {
	in := model.ExtensionEvent{
		ID: "evt_0423", Type: "project.saved", AggregateType: "project", AggregateID: "p1",
		OrderingKey: "project:p1", IdempotencyKey: "idemp0423", Source: "test",
		Payload: json.RawMessage(`{"version":1} {"version":2}`),
	}
	if _, err := normalizeEvent0206(in); err == nil {
		t.Fatal("Несколько значений JSON ошибочно приняты как одно сохраняемое событие")
	}
	in.Payload = json.RawMessage(`{"version":1} \n`)
	if _, err := normalizeEvent0206(in); err == nil {
		t.Fatal("Ошибочно приняты некорректные данные события")
	}
	in.Payload = json.RawMessage(`{"version":1}   `)
	if _, err := normalizeEvent0206(in); err != nil {
		t.Fatalf("Отклонено корректное событие с пробелами в конце: %v", err)
	}
}
