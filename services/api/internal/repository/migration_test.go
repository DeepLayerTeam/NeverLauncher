package repository

import "testing"

func TestMigrationStepGate0331(t *testing.T) {
	for _, step := range []string{"import", "cutover", "rollback", "source_assessment", "random"} {
		if _, _, err := nextStep0331(step); err == nil {
			t.Fatalf("Ошибочно принят небезопасный шаг: %s", step)
		}
	}
	next, status, err := nextStep0331("target_inventory")
	if err != nil || next != "source_assessment" || status != "prepared" {
		t.Fatalf("Недопустимый переход базового состояния %s %s %v", next, status, err)
	}
}
