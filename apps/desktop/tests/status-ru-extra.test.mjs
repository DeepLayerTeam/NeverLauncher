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
