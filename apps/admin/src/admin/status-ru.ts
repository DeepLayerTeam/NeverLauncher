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
  };
  return labels[value.toLowerCase()] ?? value;
}
