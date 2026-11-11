import { test } from 'node:test';
import assert from 'node:assert/strict';
import { statusRuDesktop } from '../src/status-ru.ts';

test('Диагностические состояния Desktop локализованы, машинные коды сохранены', () => {
  const samples = {
    'integrity-check-failed': 'Проверка целостности не пройдена',
    'not-certified': 'Не сертифицировано',
    'repaired-and-verified': 'Восстановлено и проверено',
    'pending-verification': 'Ожидается проверка',
    'retry-required': 'Необходим повтор',
  };
  for (const [value, expected] of Object.entries(samples)) {
    assert.equal(statusRuDesktop(value), expected, value);
  }
  assert.equal(statusRuDesktop('external-extension-status'), 'external-extension-status');
});

test('Дополнительные коды разных модулей локализованы без изменения самих данных', () => {
  assert.equal(statusRuDesktop('observed-not-independently-certified'), 'Наблюдалось без независимой сертификации');
  assert.equal(statusRuDesktop('source_tree_unavailable'), 'Дерево исходников недоступно');
  assert.equal(statusRuDesktop('registered-new-trust'), 'Зарегистрирована новая политика доверия');
  assert.equal(statusRuDesktop('recovery-ready'), 'Готово к восстановлению');
  assert.equal(statusRuDesktop('installation-completed-draft-created'), 'Установка завершена, черновик создан');
  assert.equal(statusRuDesktop('provider-credential-deleted'), 'Учётные данные провайдера удалены');
  assert.equal(statusRuDesktop('ci_observed_review_required'), 'Наблюдалось в CI, требуется проверка');
  assert.equal(statusRuDesktop('sandbox-not-prepared'), 'Изоляция не подготовлена');
  assert.equal(statusRuDesktop('sandbox-pid-namespace-not-enforced'), 'Изоляция пространства имён процессов не обеспечена');
  assert.equal(statusRuDesktop('macos-sandbox-invalid-network-grant'), 'Недопустимый доступ к сети в macOS');
  assert.equal(statusRuDesktop('serverbridge-nonexistent'), 'serverbridge-nonexistent');
});

// Проверяем локализацию дополнительных кодов, поступающих из Backend и нативных подсистем.
test('Ошибки ServerBridge, Guard, хоста и изоляции представлены на русском', () => {
  const examples = {
    'serverbridge_event_signature_invalid': 'Недействительная подпись события ServerBridge',
    'serverbridge_control_idempotency_key_required': 'Необходим ключ идемпотентности команды ServerBridge',
    'guard_release_revoked': 'Релиз Guard отозван',
    'host_operation_preflight_failed': 'Предварительная проверка операции хоста не пройдена',
    'sandbox-macos-helper-ready-timeout': 'Превышено время ожидания готовности помощника macOS',
    'network_capacity_revision_conflict': 'Конфликт ревизии лимита подключений',
  };
  for (const [code, expected] of Object.entries(examples)) {
    assert.equal(statusRuDesktop(code), expected, code);
  }
  assert.equal(statusRuDesktop('unknown_future_status'), 'unknown_future_status');
});
