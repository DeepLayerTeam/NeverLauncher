import { test } from 'node:test';
import assert from 'node:assert/strict';
import { adminHref, parseAdminRoute } from '../src/admin/route-links-0381.ts';
import { contextStorageKey, readSavedContext, resolveProjectContext, saveContext } from '../src/admin/project-context-0381.ts';

const catalog = {
  projects:[{id:'alpha',name:'Alpha'},{id:'beta',name:'Beta'}],
  profiles:[{id:'a-main',projectId:'alpha'},{id:'b-main',projectId:'beta'}],
  channels:[{id:'stable',projectId:'alpha'},{id:'test',projectId:'beta'}],
};
const empty = {projectId:'',profileId:'',channelId:''};
const fakeStorage = () => {
  const data = new Map();
  return {getItem:k=>data.get(k)??null,setItem:(k,v)=>data.set(k,v),removeItem:k=>data.delete(k)};
};

test('Реальные маршруты ресурсов Admin доступны по адресу и работают после перезагрузки, назад и вперёд', () => {
  const state={projectId:'alpha',profileId:'a-main',channelId:'stable'};
  for(const section of ['projects','profiles','channels','packages','release-workspace','server-bridge']) {
    const href=adminHref(section,state);
    assert.deepEqual(parseAdminRoute(href),{section,...state});
  }
  assert.deepEqual(parseAdminRoute(adminHref('profiles',{projectId:'a b/ä',profileId:'é&/ profile'})),{
    section:'profiles',projectId:'a b/ä',profileId:'é&/ profile',
  });
  assert.equal(parseAdminRoute('#/unknown').section,'dashboard');
  assert.equal(parseAdminRoute('#/%E0%A4%A').section,'dashboard');
});

test('Только авторизованный владелец и Backend используют свой сохранённый контекст', () => {
  const storage=fakeStorage();
  const alice=contextStorageKey('https://api.test:443/','alice');
  const other=contextStorageKey('https://api.test/','bob');
  const otherBackend=contextStorageKey('https://other.test/','alice');
  assert.notEqual(alice,other);
  assert.notEqual(alice,otherBackend);
  saveContext(storage,alice,{projectId:'alpha',profileId:'a-main',channelId:'stable'});
  assert.deepEqual(readSavedContext(storage,alice),{projectId:'alpha',profileId:'a-main',channelId:'stable'});
  assert.deepEqual(readSavedContext(storage,other),empty);
});

test('Переключение проекта сбрасывает устаревшие ID профиля и канала и запрещает межпроектный выбор', () => {
  const saved={projectId:'alpha',profileId:'a-main',channelId:'stable'};
  assert.deepEqual(resolveProjectContext({projectId:'beta'},saved,catalog),{projectId:'beta',profileId:'',channelId:''});
  assert.deepEqual(resolveProjectContext({projectId:'alpha'},saved,catalog),{projectId:'alpha',profileId:'',channelId:''}); // явная очистка работает
  assert.deepEqual(resolveProjectContext({projectId:'beta',profileId:'a-main',channelId:'stable'},saved,catalog),{projectId:'beta',profileId:'',channelId:''});
  assert.deepEqual(resolveProjectContext({projectId:'beta',profileId:'b-main',channelId:'test'},saved,catalog),{projectId:'beta',profileId:'b-main',channelId:'test'});
});

test('Актуальный каталог исключает неизвестные и недоступные проекты, а также удалённые ресурсы', () => {
  const saved={projectId:'alpha',profileId:'a-main',channelId:'stable'};
  assert.deepEqual(resolveProjectContext({projectId:'forbidden',profileId:'invisible'},saved,catalog),saved);
  assert.deepEqual(resolveProjectContext(saved,saved,{...catalog,profiles:[],channels:[]}),{projectId:'alpha',profileId:'',channelId:''});
  assert.deepEqual(resolveProjectContext(saved,saved,{projects:[],profiles:[],channels:[]}),empty);
  assert.deepEqual(resolveProjectContext({},empty,catalog),{projectId:'alpha',profileId:'',channelId:''});
});

test('Повреждённый, слишком большой контекст или управляющие символы не становятся доверенной навигацией', () => {
  const storage=fakeStorage();
  storage.setItem('bad','{unclosed');
  assert.deepEqual(readSavedContext(storage,'bad'),empty);
  storage.setItem('oversize',JSON.stringify({projectId:'x'.repeat(2000),profileId:'foo\u0000bar'}));
  assert.deepEqual(readSavedContext(storage,'oversize'),empty);
  assert.equal(parseAdminRoute('#/projects?project='+('x'.repeat(2000))).projectId,undefined);
});
