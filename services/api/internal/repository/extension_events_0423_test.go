package repository

import (
	"encoding/json"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// Persisting only the first of two concatenated JSON documents would silently
// change a signed/eventually-hashed event payload before durable publication.
func TestExtensionEventRejectsTrailingJSON0423(t *testing.T) {
	in := model.ExtensionEvent{
		ID: "evt_0423", Type: "project.saved", AggregateType: "project", AggregateID: "p1",
		OrderingKey: "project:p1", IdempotencyKey: "idemp0423", Source: "test",
		Payload: json.RawMessage(`{"version":1} {"version":2}`),
	}
	if _, err := normalizeEvent0206(in); err == nil {
		t.Fatal("accepted multiple JSON values as one durable event")
	}
	in.Payload = json.RawMessage(`{"version":1} \n`)
	if _, err := normalizeEvent0206(in); err == nil {
		t.Fatal("accepted malformed event payload")
	}
	in.Payload = json.RawMessage(`{"version":1}   `)
	if _, err := normalizeEvent0206(in); err != nil {
		t.Fatalf("rejected a valid event with trailing whitespace: %v", err)
	}
}
