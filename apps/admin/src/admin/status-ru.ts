/** Русские подписи состояний для отображения; значения API и фильтров не меняются. */
export function statusRu(value: string | null | undefined): string {
  if (!value) return "Неизвестно";
  const labels: Record<string, string> = {
    pending: "Ожидает", queued: "В очереди", running: "Выполняется",
    active: "Активно", inactive: "Неактивно", succeeded: "Успешно",
    completed: "Завершено", complete: "Завершено", failed: "Ошибка",
    dead: "Исчерпаны попытки", revoked: "Отозвано", disabled: "Отключено",
    enabled: "Включено", approved: "Одобрено", rejected: "Отклонено",
    cancelled: "Отменено", canceled: "Отменено", paused: "Приостановлено",
    expired: "Срок истёк", blocked: "Заблокировано", denied: "Отказано",
    healthy: "Исправно", degraded: "Сниженная работоспособность",
    unhealthy: "Неисправно", unknown: "Неизвестно", online: "В сети",
    offline: "Не в сети", stale: "Устарело", ready: "Готово",
    provisioned: "Настроено", started: "Запущено", stopped: "Остановлено",
    warning: "Предупреждение", success: "Успешно", error: "Ошибка",
    valid: "Корректно", invalid: "Некорректно", new: "Новое",
    open: "Открыто", closed: "Закрыто", verified: "Проверено",
    unverified: "Не проверено", skipped: "Пропущено", retrying: "Повторная попытка",
    absent: "Отсутствует", installed: "Установлено", uninstalled: "Удалено",
    isolated: "Изолировано", unisolated: "Без изоляции",
    enabled_unverified: "Включено, не проверено",
    fresh: "Актуально", initializing: "Инициализация", starting: "Запускается",
    stopping: "Останавливается", restarting: "Перезапускается",
    accepted: "Принято", dispatched: "Отправлено", delivered: "Доставлено",
    executed: "Выполнено", indeterminate: "Результат неизвестен",
    detached: "Отключено", available: "Доступно", unavailable: "Недоступно",
    unsupported: "Не поддерживается", denied_by_policy: "Запрещено политикой",
    none: "Нет", ok: "Норма", enforced: "Применено",
    "not-enforced": "Не применяется", "os-isolated": "Изолировано средствами ОС",
    "legacy-unisolated": "Без подтверждённой изоляции ОС",
  };
  return labels[value.toLowerCase()] ?? value;
}
