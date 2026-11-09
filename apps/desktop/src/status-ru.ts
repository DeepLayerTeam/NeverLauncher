/** Локализация пользовательских статусов обращений; коды API сохраняются. */
export function statusRuDesktop(value: string | null | undefined): string {
  const labels: Record<string, string> = {
    pending: "Ожидает", open: "Открыто", reviewed: "Рассмотрено",
    approved: "Одобрено", rejected: "Отклонено", denied: "Отказано",
    resolved: "Решено", closed: "Закрыто", failed: "Ошибка",
    active: "Активно", revoked: "Отозвано", expired: "Срок истёк",
    healthy: "Исправен", degraded: "Работает с ограничениями",
    unhealthy: "Неисправен", ready: "Готов", unavailable: "Недоступен",
    online: "В сети", offline: "Не в сети", unknown: "Неизвестно",
    valid: "Корректно", invalid: "Некорректно", ok: "В порядке",
    missing: "Отсутствует", corrupt: "Повреждён", mismatch: "Не совпадает",
    queued: "В очереди", running: "Выполняется", completed: "Завершено",
    stopped: "Остановлен", disabled: "Отключено", enabled: "Включено",
  };
  return value ? (labels[value.toLowerCase()] ?? value) : "Неизвестно";
}
