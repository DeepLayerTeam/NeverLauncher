/** Audit navigation stays in the same authenticated Admin session. */
export function auditHref(query: string): string {
  return `#/audit?query=${encodeURIComponent(query)}`;
}
export function recoveryAdvice(error: string): string {
  const lower = error.toLowerCase();
  if (lower.includes('403') || lower.includes('permission') || lower.includes('forbidden')) return 'Запросите полномочия для выбранного объекта.';
  if (lower.includes('401') || lower.includes('step-up') || lower.includes('fresh') || lower.includes('mfa')) return 'Выполните новый вход или passkey step-up.';
  if (lower.includes('409') || lower.includes('conflict')) return 'Обновите состояние объекта перед новым действием.';
  if (lower.includes('timeout') || lower.includes('network') || lower.includes('fetch')) return 'Проверьте сервер и аудит перед повтором: запрос мог быть исполнен.';
  return 'Проверьте причину отказа и обновите данные.';
}
