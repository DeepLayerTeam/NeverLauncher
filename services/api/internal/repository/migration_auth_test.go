package repository

import (
	"strings"
	"testing"

	gi "gitflic.ru/skif4er/launcher/services/api/internal/gravitidentity"
)

func TestMigratedSQLUserIDDoesNotCollideAcrossSources0444(t *testing.T) {
	a := gi.Account{Provider: "sql", SourceID: "1", UUID: "11111111-2222-4333-8444-555555555555"}
	b := gi.Account{Provider: "sql", SourceID: "1", UUID: "99999999-2222-4333-8444-555555555555"}
	if migratedUserID0335(a) == migratedUserID0335(b) {
		t.Fatal("Совпали идентификаторы исходных строк SQL с разных серверов")
	}
	if migratedUserID0335(a) == legacyMigratedSQLUserID0335(a) {
		t.Fatal("Старый небезопасный идентификатор пользователя SQL повторно использован при импорте")
	}
	a.SourceID = "99"
	if migratedUserID0335(a) != "gravit-sql-"+strings.ReplaceAll(a.UUID, "-", "") {
		t.Fatal("Идентификатор строки исходной БД влияет на личность Minecraft")
	}
}
