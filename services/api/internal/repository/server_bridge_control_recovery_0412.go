package repository

import "gitflic.ru/skif4er/neverlauncher/services/api/internal/model"

// An indeterminate result reported by an agent is FINAL. Only an indeterminate
// result synthesized because a delivery lease expired may be replaced with a
// matching, delayed durable receipt from the ORIGINAL leased execution.
func recoverableServerBridgeLease0412(c model.ServerBridgeControlCommand) bool {
	if c.Status != "indeterminate" || len(c.Result) != 0 || c.LeaseToken == "" || c.LeaseOwner == "" {
		return false
	}
	switch c.Error {
	case "delivered command expired without proof of completion",
		"delivery lease expired without proof of completion",
		"delivery belongs to a superseded runtime identity",
		"delivered command lost lease/runtime before ACK",
		"delivered command lost lease without proof of completion":
		return true
	}
	return false
}
