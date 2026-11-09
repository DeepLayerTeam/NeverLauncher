import { test } from 'node:test';
import assert from 'node:assert/strict';
import { statusRu } from '../src/admin/status-ru.ts';

test('Коды основных событий аудита отображаются по-русски', () => {
  const samples = {
    'auth:login': 'Вход в учётную запись',
    'auth:refresh:reuse-detected': 'Обнаружено повторное использование токена',
    'release:publish': 'Публикация выпуска',
    'serverbridge:handoff:denied': 'Передача игрока между серверами отклонена',
    'serverbridge:validate-join:allowed': 'Подключение игрока разрешено',
    'guard:attestation:verified': 'Аттестация защиты подтверждена',
    'validation-attestation:key-revoked': 'Ключ подтверждения проверки отозван',
    'installed-and-verified': 'Установлено и проверено',
  };
  for (const [code, expected] of Object.entries(samples)) {
    assert.equal(statusRu(code), expected, code);
  }
});

test('Отображение кода не меняет идентификаторы событий и неизвестные значения', () => {
  const originalCode = 'auth:device:revoke';
  assert.equal(statusRu(originalCode), 'Отзыв доверия к устройству');
  assert.equal(originalCode, 'auth:device:revoke');
  assert.equal(statusRu('external:custom:event'), 'external:custom:event');
  assert.equal(statusRu(undefined), 'Неизвестно');
});
