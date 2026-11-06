//go:build !launcher_nopgx

package repository

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Успешная проверка подписи не должна позволять записать аппаратный допуск для
// отозванного или перепривязанного сеанса. Второе соединение PostgreSQL имитирует
// продолжающуюся аттестацию, пока другая реплика API отзывает доверие.
func TestTPMProofCannotSurviveSessionRevocation0436(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires real disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	first, ok := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
	if !ok {
		t.Fatal("требуется PostgreSQL")
	}
	defer first.db.Close()
	second, ok := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
	if !ok {
		t.Fatal("Требуется второе соединение PostgreSQL")
	}
	defer second.db.Close()
	if _, err := first.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	user, device, session, family := "tpm-user-"+suffix, "tpm-device-"+suffix, "tpm-session-"+suffix, "tpm-family-"+suffix
	fp := strings.Repeat("a", 64)
	rootFP, akFP := strings.Repeat("b", 64), strings.Repeat("c", 64)
	_, err := first.db.ExecContext(ctx, `INSERT INTO users(id,email,display_name,role_id,status,password_hash) VALUES($1,$2,'TPM Proof Test','player','active','test-hash')`, user, user+"@example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer first.db.ExecContext(context.Background(), `DELETE FROM users WHERE id=$1`, user)
	_, err = first.db.ExecContext(ctx, `INSERT INTO trusted_devices(id,user_id,name,status,trust_state,key_algorithm,key_binding,hardware_provider,public_key,key_fingerprint,platform) VALUES($1,$2,'TPM Test','active','verified','p256','hardware','WindowsTpm','p256-test-public',$3,'windows')`, device, user, fp)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := first.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO auth_sessions(id,user_id,email,role_id,refresh_family_id,status,expires_at,trusted_device_id,device_trust_state,binding_epoch) VALUES($1,$2,$3,'player',$4,'active',now()+interval '1 hour',$5,'verified',7)`, session, user, user+"@example.test", family, device)
	if err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO refresh_token_families(id,session_id,user_id) VALUES($1,$2,$3)`, family, session, user)
	}
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	hw := model.DeviceHardwareEvidence{UserID: user, DeviceID: device, SessionID: session, BindingEpoch: 7, KeyFingerprint: fp, RootID: "operator", RootFingerprint: rootFP, AKFingerprint: akFP, ChallengeID: "htc-" + suffix, VerifiedAt: now, ExpiresAt: now.Add(time.Hour)}
	quote := model.MeasuredBootEvidence0315{UserID: user, DeviceID: device, SessionID: session, BindingEpoch: 7, KeyFingerprint: fp, RootID: "operator", RootFingerprint: rootFP, AKFingerprint: akFP, PolicyID: "prod", PolicyHash: strings.Repeat("d", 64), PCRDigest: strings.Repeat("e", 64), ChallengeID: "mpc-" + suffix, VerifiedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	if err = second.SaveHardwareEvidence(ctx, hw); err != nil {
		t.Fatalf("Действующее аппаратное подтверждение отклонено: %v", err)
	}
	if err = second.SaveMeasuredBoot0315(ctx, quote); err != nil {
		t.Fatalf("Действующий Quote отклонён: %v", err)
	}
	if _, err = first.db.ExecContext(ctx, `UPDATE auth_sessions SET binding_epoch=8 WHERE id=$1`, session); err != nil {
		t.Fatal(err)
	}
	hw.ChallengeID += "-epoch"
	quote.ChallengeID += "-epoch"
	if err = second.SaveHardwareEvidence(ctx, hw); err == nil {
		t.Fatal("Аппаратное подтверждение сохранено для устаревшей эпохи")
	}
	if err = second.SaveMeasuredBoot0315(ctx, quote); err == nil {
		t.Fatal("Подтверждение измеренной загрузки сохранено для устаревшей эпохи")
	}
	if _, err = first.db.ExecContext(ctx, `UPDATE auth_sessions SET status='revoked',revoked_at=now(),revoked_reason='proof-test' WHERE id=$1`, session); err != nil {
		t.Fatal(err)
	}
	hw.BindingEpoch = 8
	quote.BindingEpoch = 8
	hw.ChallengeID += "-revoked"
	quote.ChallengeID += "-revoked"
	if err = second.SaveHardwareEvidence(ctx, hw); err == nil {
		t.Fatal("Отозванная сессия сохранила аппаратное подтверждение")
	}
	if err = second.SaveMeasuredBoot0315(ctx, quote); err == nil {
		t.Fatal("Отозванная сессия сохранила подтверждение измеренной загрузки")
	}
}
