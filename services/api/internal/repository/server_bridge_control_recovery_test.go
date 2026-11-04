package repository

import (
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"testing"
)

func TestSyntheticLeaseRecoveryGate0412(t *testing.T) {
	c := model.ServerBridgeControlCommand{Status: "indeterminate", Error: "delivery lease expired without proof of completion", LeaseOwner: "channel", LeaseToken: "token"}
	if !recoverableServerBridgeLease0412(c) {
		t.Fatal("synthetic status must permit late authenticated receipt")
	}
	c.Error = "agent reported indeterminate"
	if recoverableServerBridgeLease0412(c) {
		t.Fatal("actual agent uncertainty may not be overwritten")
	}
	c.Error = "delivery lease expired without proof of completion"
	c.Result = map[string]string{"saved": "false"}
	if recoverableServerBridgeLease0412(c) {
		t.Fatal("nonempty result may not be overwritten")
	}
	c.Result = nil
	c.LeaseToken = ""
	if recoverableServerBridgeLease0412(c) {
		t.Fatal("missing token must not authorize recovery")
	}
}
