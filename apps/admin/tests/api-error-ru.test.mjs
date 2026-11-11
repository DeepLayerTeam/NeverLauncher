import { test } from 'node:test';
import assert from 'node:assert/strict';
import { networkErrorRu, httpStatusRu } from '../src/api/client.ts';

test('Сетевые ошибки браузера отображаются на русском', () => {
  assert.equal(networkErrorRu(new TypeError('Failed to fetch')), 'Не удалось выполнить сетевой запрос');
  assert.equal(networkErrorRu(new Error('NetworkError when attempting to fetch resource.')), 'Сетевая ошибка при обращении к серверу');
  assert.equal(networkErrorRu(new Error('The operation was aborted.')), 'Операция прервана');
  assert.equal(networkErrorRu(new Error('Проверка ключа не пройдена')), 'Проверка ключа не пройдена');
});

test('HTTP-коды имеют русские пояснения без изменения статуса протокола', () => {
  assert.equal(httpStatusRu({ status: 404 }), 'HTTP 404: Не найдено');
  assert.equal(httpStatusRu({ status: 503 }), 'HTTP 503: Сервис временно недоступен');
  assert.equal(httpStatusRu({ status: 599 }), 'HTTP 599: Ошибка запроса к серверу');
});

test('Ошибки сетевого транспорта и сертификатов получают русские пояснения', () => {
  assert.equal(networkErrorRu(new Error('net::ERR_CONNECTION_REFUSED')), 'Соединение с сервером отклонено (ERR_CONNECTION_REFUSED)');
  assert.equal(networkErrorRu(new Error('net::ERR_CERT_AUTHORITY_INVALID')), 'Не удалось проверить сертификат защищённого соединения');
  assert.equal(networkErrorRu(new Error('ENOTFOUND api.example.invalid')), 'Не удалось определить адрес сервера (ошибка DNS)');
  assert.equal(networkErrorRu(new Error('The network connection was lost.')), 'Сетевое соединение потеряно или недоступно');
});
