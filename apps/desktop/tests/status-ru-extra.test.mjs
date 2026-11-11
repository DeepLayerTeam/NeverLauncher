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
