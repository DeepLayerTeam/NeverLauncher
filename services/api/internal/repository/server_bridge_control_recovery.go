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
	case "Срок действия доставленной команды истёк без подтверждения завершения",
		"Срок аренды доставки истёк без подтверждения завершения",
		"Доставка привязана к устаревшему идентификатору Runtime",
		"Доставленная команда утратила аренду или среду выполнения до подтверждения ACK",
		"Выданная команда потеряла аренду без подтверждения завершения":
		return true
	}
	return false
}
