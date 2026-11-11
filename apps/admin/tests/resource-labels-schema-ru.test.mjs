import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resourceFieldRu, resourceBooleanRu } from '../src/components/resource-labels.ts';

test('Отображаемые поля API имеют русские названия без изменения исходных ключей', () => {
  const samples = {
    apiVersion: 'Версия API',
    evidenceReference: 'Ссылка на подтверждение',
    minecraftAccessToken: 'Токен доступа Minecraft',
    worldSha256: 'SHA-256 мира',
    clientToken: 'Токен клиента',
    playersMax: 'Максимум игроков',
    reconciliationEvidenceSha256: 'SHA-256 подтверждения сверки',
  };
  for (const [field, expected] of Object.entries(samples)) {
    assert.equal(resourceFieldRu(field), expected);
  }
  assert.equal(resourceFieldRu('customThirdPartyField'), 'customThirdPartyField');
  assert.equal(resourceBooleanRu(true), 'Да');
  assert.equal(resourceBooleanRu(false), 'Нет');
});
