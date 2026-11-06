package main

import "testing"

func TestCutoverCheckRequiresAllFlags0475(t *testing.T) {
	if runPGCutoverCheck0475([]string{"--source-sha256", "abc", "--project", "x"}) != 2 {
		t.Fatal("Ошибочно принят неполный запрос проверки переключения")
	}
}
