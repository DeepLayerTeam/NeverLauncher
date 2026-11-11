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

test('Состояния сборки, безопасности и ServerBridge отображаются по-русски', () => {
  const samples = {
    'integrity-check-failed': 'Проверка целостности не пройдена',
    'not-certified': 'Не сертифицировано',
    'repaired-and-verified': 'Восстановлено и проверено',
    'handoff-denied': 'Передача подключения отклонена',
    'manual-intervention-required': 'Требуется вмешательство оператора',
    'events-acknowledged': 'Получение событий подтверждено',
  };
  for (const [value, expected] of Object.entries(samples)) {
    assert.equal(statusRu(value), expected, value);
  }
});

test('Дополнительные коды разных модулей локализованы без изменения самих данных', () => {
  assert.equal(statusRu('observed-not-independently-certified'), 'Наблюдалось без независимой сертификации');
  assert.equal(statusRu('source_tree_unavailable'), 'Дерево исходников недоступно');
  assert.equal(statusRu('registered-new-trust'), 'Зарегистрирована новая политика доверия');
  assert.equal(statusRu('recovery-ready'), 'Готово к восстановлению');
  assert.equal(statusRu('installation-completed-draft-created'), 'Установка завершена, черновик создан');
  assert.equal(statusRu('provider-credential-deleted'), 'Учётные данные провайдера удалены');
  assert.equal(statusRu('ci_observed_review_required'), 'Наблюдалось в CI, требуется проверка');
  assert.equal(statusRu('sandbox-not-prepared'), 'Изоляция не подготовлена');
  assert.equal(statusRu('sandbox-pid-namespace-not-enforced'), 'Изоляция пространства имён процессов не обеспечена');
  assert.equal(statusRu('macos-sandbox-invalid-network-grant'), 'Недопустимый доступ к сети в macOS');
  assert.equal(statusRu('serverbridge-nonexistent'), 'serverbridge-nonexistent');
});
