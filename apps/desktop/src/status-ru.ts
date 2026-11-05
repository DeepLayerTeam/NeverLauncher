/** Локализация пользовательских статусов обращений; коды API сохраняются. */
export function statusRuDesktop(value: string | null | undefined): string {
  const labels: Record<string, string> = {
    pending: "Ожидает", open: "Открыто", reviewed: "Рассмотрено",
    approved: "Одобрено", rejected: "Отклонено", denied: "Отказано",
    resolved: "Решено", closed: "Закрыто", failed: "Ошибка",
    active: "Активно", revoked: "Отозвано", expired: "Срок истёк",
  };
  return value ? (labels[value.toLowerCase()] ?? value) : "Неизвестно";
}
