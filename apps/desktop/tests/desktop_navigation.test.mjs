import test from 'node:test';
import assert from 'node:assert/strict';
import {navigation0353,restoreScreen0353,permittedScreen0353,filterHistory0353,chooseProject0353,chooseProfile0353,canSelectServer0353,gameBaseDirectory0353} from '../build-tests/desktop_navigation.js';
test('Каждый пользовательский экран имеет уникальное имя и не является исключительно техническим',()=>{
  assert.equal(new Set(navigation0353.map(item=>item.id)).size,navigation0353.length);
  for(const screen of ['accounts','servers','builds','optionalMods','textures','download','history','settings','diagnostics']) assert.ok(navigation0353.some(item=>item.id===screen));
  assert.ok(!navigation0353.some(item=>['auth','profile','logs','projects'].includes(item.id)));
});
test('Сохранённый экран не обходит подписанную первоначальную настройку и не допускает неизвестные экраны',()=>{
  assert.equal(restoreScreen0353('history',true),'history');
  assert.equal(restoreScreen0353('history',false),'firstRun');
  assert.equal(restoreScreen0353('javascript:evil',true),'overview');
  assert.equal(restoreScreen0353('firstRun',true),'overview');
  assert.equal(permittedScreen0353('builds',true,false,false),false);
  assert.equal(permittedScreen0353('accounts',true,false,false),true);
  assert.equal(permittedScreen0353('overview',true,true,false),true);
  assert.equal(permittedScreen0353('overview',false,false,false),true);
  assert.equal(permittedScreen0353('accounts',true,true,true),false);
  assert.equal(permittedScreen0353('firstRun',true,false,true),true);
});
test('Выбор проекта или профиля отклоняет устаревшие и удалённые ID, сохраняя безопасный отказ для подписанной привязки',()=>{
  const list=[{id:'a'},{id:'b'}];
  assert.equal(chooseProject0353('unused',list,'b'),'b');
  assert.equal(chooseProject0353('unused',list,'removed'),'a');
  assert.equal(chooseProject0353('unused',list,'b','removed'),'');
  assert.equal(chooseProfile0353('unused',list,'b','a'),'a');
  assert.equal(chooseProfile0353('unused',[], 'b'),'');
});
test('Выбор допускает только активные подходящие серверы; закреплённый сервер нельзя подменить',()=>{
  const list=[{id:'main',status:'active'},{id:'retired',status:'revoked'}];
  assert.equal(canSelectServer0353('main',list,''),true);
  assert.equal(canSelectServer0353('retired',list,''),false);
  assert.equal(canSelectServer0353('foreign',list,''),false);
  assert.equal(canSelectServer0353('main',list,'fixed'),false);
  assert.equal(canSelectServer0353('',list,'fixed'),false);
  assert.equal(canSelectServer0353('main',list,'main'),true);
});
test('История запусков сортируется по времени без изменения сохранённых свидетельств и точно фильтрует успешные состояния',()=>{
  const rows=[{startedAt:'bad',success:false},{startedAt:'2026-10-27T01:00:00Z',success:true},{startedAt:'2026-10-28T01:00:00Z',success:false}];
  assert.deepEqual(filterHistory0353(rows,'failed').map(item=>item.startedAt),['2026-10-28T01:00:00Z','bad']);
  assert.equal(filterHistory0353(rows,'success').length,1);
  assert.equal(rows[0].startedAt,'bad');
});

test('Базовый каталог профиля не должен сокращать похожие или частичные идентификаторы',()=>{
  assert.equal(gameBaseDirectory0353('/home/u/projects/a/b','a','b'),'/home/u/projects');
  assert.equal(gameBaseDirectory0353('C:\\Games\\p\\client','p','client'),'C:\\Games');
  assert.equal(gameBaseDirectory0353('/home/u/projects/a/beta','a','b'),'/home/u/projects/a/beta');
  assert.equal(gameBaseDirectory0353('/home/u/custom','a','b'),'/home/u/custom');
});
