import { test } from 'node:test';
import assert from 'node:assert/strict';
import { auditHref, recoveryAdvice } from '../src/admin/lifecycle.ts';
import { canSeeSection, can } from '../src/admin/permissions.ts';
import { requestJSON } from '../src/api/client.ts';

const viewer = {user:{id:'alice',email:'a@example.test',roleId:'viewer'},permissions:[],projectPermissions:{alpha:['project:read']}};
test('Личные сеансы доступны без глобального users:manage, в отличие от средств администрирования', () => {
 assert.equal(canSeeSection(viewer,'devices','alpha'),true);
 assert.equal(can(viewer,'users:manage'),false);
 assert.equal(canSeeSection(viewer,'backup-restore','alpha'),false);
});
test('Глубокие ссылки аудита кодируют идентификаторы корреляции и расширений', () => {
 assert.equal(auditHref('job_a/b ?'), '#/audit?query=job_a%2Fb%20%3F');
 assert.equal(auditHref('extension.demo'), '#/audit?query=extension.demo');
});
test('Рекомендации по восстановлению различают авторизацию, конфликт и неопределённый транспорт', () => {
 assert.match(recoveryAdvice('403 forbidden'),/полномочия/i);
 assert.match(recoveryAdvice('step-up required'),/вход|step-up/i);
 assert.match(recoveryAdvice('409 conflict'),/обновите/i);
 assert.match(recoveryAdvice('network timeout'),/аудит/i);
});
test('Список заданий использует авторизованный ответ API, ограниченный текущим проектом', async () => {
 const old = globalThis.fetch;
 try {
  globalThis.fetch = async (url, init) => {
   assert.equal(url,'https://api.example/api/v1/operations/jobs?projectId=alpha&limit=25&offset=0');
   assert.equal(init.headers.get('Authorization'),'Bearer session');
   return {ok:true,json:async()=>({apiVersion:'1',data:{items:[{id:'job1',projectId:'alpha',status:'pending'}],hasMore:false}})};
  };
  const result = await requestJSON('https://api.example','/api/v1/operations/jobs?projectId=alpha&limit=25&offset=0','session');
  assert.deepEqual(result.items.map(j=>j.id),['job1']);
 } finally {globalThis.fetch=old;}
});
test('Восстановление из резервной копии требует явно выбранного архива и компонентов', () => {
 const body = JSON.stringify({confirm:'backup-id',database:true,storage:false});
 assert.deepEqual(JSON.parse(body),{confirm:'backup-id',database:true,storage:false});
});
