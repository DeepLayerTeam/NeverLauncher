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
		t.Fatal("same upstream SQL row ID from different servers collided")
	}
	if migratedUserID0335(a) == legacyMigratedSQLUserID0335(a) {
		t.Fatal("old unsafe SQL user ID reused for new imports")
	}
	a.SourceID = "99"
	if migratedUserID0335(a) != "gravit-sql-"+strings.ReplaceAll(a.UUID, "-", "") {
		t.Fatal("source DB row ID affects Minecraft identity")
	}
}
