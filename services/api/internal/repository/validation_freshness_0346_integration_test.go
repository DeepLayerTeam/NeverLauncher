//go:build !launcher_nopgx

package repository

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestV05PostgresDurableChallengeAndKeyRevocation0346(t *testing.T) {
	dsn := os.Getenv("NEVERLAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	r := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer r.db.Close()
	if _, err := r.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	project := "v05-" + strings.Repeat("7", 8) + time.Now().UTC().Format("150405.000000000")
	release := project + "-release"
	if _, err := r.db.ExecContext(ctx, `INSERT INTO projects(id,name) VALUES($1,$1)`, project); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = r.db.ExecContext(context.Background(), `DELETE FROM package_validation_challenges_0346 WHERE package_id=$1`, release)
		_, _ = r.db.ExecContext(context.Background(), `DELETE FROM release_versions WHERE id=$1`, release)
		_, _ = r.db.ExecContext(context.Background(), `DELETE FROM projects WHERE id=$1`, project)
	}()
	if _, err := r.db.ExecContext(ctx, `INSERT INTO release_versions(id,project_id,profile_id,channel,version,status,manifest) VALUES($1,$2,'vanilla','dev','1','draft','{}'::jsonb)`, release, project); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	c := model.ValidationChallenge0346{RunID: project + "-run", Nonce: strings.Repeat("a", 64), PackageID: release, ProjectID: project, ManifestSHA256: strings.Repeat("b", 64), ArtifactSHA256: strings.Repeat("c", 64), TargetMatrixSHA256: strings.Repeat("d", 64), IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := r.SaveValidationChallenge0346(ctx, c); err != nil {
		t.Fatal(err)
	}
	restored, err := r.GetValidationChallenge0346(ctx, c.RunID)
	if err != nil || restored.Nonce != c.Nonce || !restored.IssuedAt.Equal(c.IssuedAt) || restored.TargetMatrixSHA256 != c.TargetMatrixSHA256 {
		t.Fatalf("challenge not durably bound: %+v %v", restored, err)
	}
	if err := r.SaveValidationChallenge0346(ctx, c); err == nil {
		t.Fatal("replayed run accepted")
	}
	sameNonce := c
	sameNonce.RunID += "-another"
	if err := r.SaveValidationChallenge0346(ctx, sameNonce); err == nil {
		t.Fatal("reused nonce accepted for different run")
	}
	fp := strings.Repeat("e", 64)
	if err := r.RevokeValidationKey0346(ctx, fp, "operator", "confirmed key compromise"); err != nil {
		t.Fatal(err)
	}
	revoked, err := r.IsValidationKeyRevoked0346(ctx, fp)
	if err != nil || !revoked {
		t.Fatal("revocation not visible to SQL reader", err)
	}
	// Key revocations are global and permanent; no DELETE/restore endpoint exists.
}
