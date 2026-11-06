package repository

import (
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"testing"
)

func TestSyntheticLeaseRecoveryGate0412(t *testing.T) {
	c := model.ServerBridgeControlCommand{Status: "indeterminate", Error: "delivery lease expired without proof of completion", LeaseOwner: "channel", LeaseToken: "token"}
	if !recoverableServerBridgeLease0412(c) {
		t.Fatal("Синтетический статус должен допускать позднее получение подтверждённой квитанции")
	}
	c.Error = "agent reported indeterminate"
	if recoverableServerBridgeLease0412(c) {
		t.Fatal("Нельзя перезаписывать неопределённое состояние реального агента")
	}
	c.Error = "delivery lease expired without proof of completion"
	c.Result = map[string]string{"saved": "false"}
	if recoverableServerBridgeLease0412(c) {
		t.Fatal("Нельзя перезаписывать непустой результат")
	}
	c.Result = nil
	c.LeaseToken = ""
	if recoverableServerBridgeLease0412(c) {
		t.Fatal("Отсутствующий токен не должен разрешать восстановление")
	}
}
