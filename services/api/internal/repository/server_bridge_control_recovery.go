package repository

import "gitflic.ru/skif4er/launcher/services/api/internal/model"

// Неопределённый результат от агента ОКОНЧАТЕЛЕН. Заменить совпадающей запоздалой
// устойчивой квитанцией ИСХОДНОГО арендуемого выполнения можно только
// неопределённый результат, созданный искусственно из-за истечения аренды доставки.
func recoverableServerBridgeLease0412(c model.ServerBridgeControlCommand) bool {
	if c.Status != "indeterminate" || len(c.Result) != 0 || c.LeaseToken == "" || c.LeaseOwner == "" {
		return false
	}
	switch c.Error {
	case "delivered command expired without proof of completion",
		"delivery lease expired without proof of completion",
		"Доставка привязана к устаревшему идентификатору Runtime",
		"delivered command lost lease/runtime before ACK",
		"Выданная команда потеряла аренду без подтверждения завершения":
		return true
	}
	return false
}
