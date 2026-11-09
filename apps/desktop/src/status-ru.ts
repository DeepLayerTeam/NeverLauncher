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
    allow: "Разрешено", deny: "Отказано", verified: "Проверено",
    "not-verified": "Не проверено", "tpm-ak-certified": "Подтверждено через TPM",
    "client-reported": "Заявлено клиентом (без проверки сервером)",
    "device-not-verified": "Устройство не прошло проверку",
    "session-device-binding-missing": "Сессия не привязана к устройству",
    "challenge-response-expired-or-invalid": "Проверка устройства недействительна или просрочена",
    "remote-hardware-verifier-unavailable": "Удалённая проверка оборудования недоступна",
    "guard-runtime-evidence-unavailable": "Нет подтверждения от защитного модуля",
    "macos-device-key-provenance-unsupported": "Проверка происхождения ключа macOS не поддерживается",
    "macos-app-attest-not-bound-to-device-identity": "App Attest не привязан к идентификатору устройства",
    "login-or-verify-device": "Войдите заново или подтвердите устройство",
    "use-standard-profile-or-supported-verified-device": "Используйте стандартный профиль или поддерживаемое проверенное устройство",
    "use-standard-profile-or-recover-device-with-fresh-passkey-then-reattest": "Используйте стандартный профиль либо восстановите устройство с новым ключом входа и повторите аттестацию",
  };
  return value ? (labels[value.toLowerCase()] ?? value) : "Неизвестно";
}
