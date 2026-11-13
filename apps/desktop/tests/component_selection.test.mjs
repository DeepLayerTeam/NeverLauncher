// Запуск `node --test` после транспиляции чистого модуля выбора через tsc.
import test from 'node:test';
import assert from 'node:assert/strict';
import {parseChoice0247,encodeChoice0247,proposeChoice0247} from '../build-tests/component_selection.js';
test('Канонические варианты остаются стабильными, дубликаты отклоняются',()=>{
  assert.equal(encodeChoice0247(parseChoice0247('@custom:v1:quality:+iris,-optifine')),'@custom:v1:quality:+iris,-optifine');
  assert.throws(()=>parseChoice0247('@custom:v1::+a,+a'),/повторная/);
  assert.throws(()=>parseChoice0247('@custom:v1::+unknown/evil'),/Некорректная/);
});
test('Выбор несовместимого мода последовательно исключает зависимые моды',()=>{
  const cat=[{id:'iris',name:'Iris',dependencies:[{id:'sodium'}]},{id:'sodium',name:'Sodium',conflicts:[{id:'optifine'}]},{id:'optifine',name:'OptiFine'}];
  const choice=proposeChoice0247('',cat,['iris','sodium'],'optifine',true);
  assert.deepEqual(choice.removed,['iris','sodium']);
  assert.deepEqual(choice.added,['optifine']);
});
test('Удаление обязательного компонента запрещено',()=>{
  assert.throws(()=>proposeChoice0247('',[{id:'core',name:'core',required:true}],['core'],'core',false),/нельзя/);
});

test('Ограничения SemVer соответствуют нативному разрешению версий, включая диапазоны и предрелизы',async()=>{
  const {matchesVersion0247} = await import('../build-tests/component_selection.js');
  for(const [version,range,expected] of [
    ['1.2.3','>=1.0.0 <2.0.0',true], ['2.0.0','>=1.0.0 <2.0.0',false],
    ['0.5.2','^0.5.0',true], ['0.6.0','^0.5.0',false],
    ['0.0.5','^0.0.4',false], ['1.5.1','~1.5.0',true],
    ['1.6.0','~1.5.0',false], ['1.3.0','<1.0.0 || >=1.3.0',true],
    ['1.2.3-alpha.1','<1.2.3',true], ['1.2.3','=1.2.3+metadata',true],
    ['2.2.0','>=2.0.0',true], ['1.9.9','>=2.0.0',false],
  ]) assert.equal(matchesVersion0247(version,range),expected,`${version} ${range}`);
  for(const range of ['>=bad','^1.2','=>1.2.0','   ||  >1.2.0'])
    assert.throws(()=>matchesVersion0247('1.2.3',range));
});

test('Направленный конфликт версий удаляет уже установленный несовместимый мод',()=>{
  const cat=[
    {id:'newrenderer',name:'New',version:'2.1.0',conflicts:[{id:'oldrenderer',versionRange:'>=1.5.0 <2.0.0'}]},
    {id:'oldrenderer',name:'Old',version:'1.8.0'},
    {id:'addon',name:'Addon',version:'1.0.0',dependencies:[{id:'oldrenderer'}]},
  ];
  const candidate=proposeChoice0247('quality',cat,['oldrenderer','addon'],'newrenderer',true);
  assert.deepEqual(candidate.removed,['oldrenderer','addon']);
  assert.deepEqual(candidate.added,['newrenderer']);
  assert.equal(candidate.choice,'@custom:v1:quality:-addon,+newrenderer,-oldrenderer');
});

test('Если направленный конфликт версий не совпадает, оба мода сохраняются',()=>{
  const cat=[
    {id:'updated',name:'Updated',version:'2.1.0',conflicts:[{id:'legacy',versionRange:'<2.0.0'}]},
    {id:'legacy',name:'Legacy',version:'2.0.0'},
  ];
  const candidate=proposeChoice0247('',cat,['legacy'],'updated',true);
  assert.deepEqual(candidate.removed,[]);
  assert.deepEqual(candidate.added,['updated']);
});

test('Зависимость нового мода конфликтует с установленным модом и удаляет зависимые компоненты',()=>{
  const cat=[
    {id:'newaddon',name:'New',version:'1.0.0',dependencies:[{id:'engine'}]},
    {id:'engine',name:'Engine',version:'2.0.0',conflicts:[{id:'legacy',versionRange:'^1.0.0'}]},
    {id:'legacy',name:'Legacy',version:'1.4.0'},
    {id:'legacyaddon',name:'Old addon',version:'1.0.0',dependencies:[{id:'legacy'}]},
  ];
  const candidate=proposeChoice0247('',cat,['legacy','legacyaddon'],'newaddon',true);
  assert.deepEqual(candidate.removed,['legacy','legacyaddon']);
  assert.deepEqual(candidate.added,['newaddon','engine']);
  assert.doesNotMatch(candidate.choice,/\+engine/); // нативный компонент раскрывает подписанные зависимости
});

test('Переключение взаимоисключающих движков удаляет старый движок и зависимые моды',()=>{
  const cat=[
    {id:'renderer-a',name:'A',exclusiveGroup:'renderer'},
    {id:'renderer-b',name:'B',exclusiveGroup:'renderer'},
    {id:'addon',name:'Addon',dependencies:[{id:'renderer-a'}]},
  ];
  const result=proposeChoice0247('',cat,['renderer-a','addon'],'renderer-b',true);
  assert.deepEqual(result.removed,['renderer-a','addon']);
});

test('Конфликт с обязательным компонентом отклоняется без альтернативного варианта',()=>{
  const cat=[
    {id:'newmod',name:'New',conflicts:[{id:'core'}]},
    {id:'core',name:'Core',required:true},
  ];
  assert.throws(()=>proposeChoice0247('',cat,['core'],'newmod',true),/обязательным/);
});

test('Невыполнимые зависимости отклоняются до установки',()=>{
  const cat=[
    {id:'newmod',name:'New',dependencies:[{id:'engine',versionRange:'^2.0.0'}]},
    {id:'engine',name:'Engine',version:'1.9.0'},
  ];
  assert.throws(()=>proposeChoice0247('',cat,[],'newmod',true),/требует/);
  const missing=[{id:'newmod',name:'New',dependencies:[{id:'absent'}]}];
  assert.throws(()=>proposeChoice0247('',missing,[],'newmod',true),/отсутствует/);
});

test('Две зависимости запрошенного мода не должны конфликтовать друг с другом',()=>{
  const cat=[
    {id:'newmod',name:'New',dependencies:[{id:'a'},{id:'b'}]},
    {id:'a',name:'A',exclusiveGroup:'engine'},
    {id:'b',name:'B',exclusiveGroup:'engine'},
  ];
  assert.throws(()=>proposeChoice0247('',cat,[],'newmod',true),/Несовместимые зависимости/);
});

test('Отключение зависимости удаляет все активные зависящие от неё компоненты',()=>{
  const cat=[
    {id:'base',name:'Base'},
    {id:'mid',name:'Mid',dependencies:[{id:'base'}]},
    {id:'top',name:'Top',dependencies:[{id:'mid'}]},
  ];
  const result=proposeChoice0247('quality',cat,['base','mid','top'],'base',false);
  assert.deepEqual(result.removed,['base','mid','top']);
});

test('Ранее заданное исключение отменяется ради новой подписанной зависимости',()=>{
  const cat=[
    {id:'mod',name:'Mod',dependencies:[{id:'helper'}]},
    {id:'helper',name:'Helper',visible:false},
  ];
  const result=proposeChoice0247('@custom:v1::\x2dhelper',cat,[],'mod',true);
  assert.deepEqual(result.added,['mod','helper']);
  assert.equal(result.choice,'@custom:v1::+mod');
});
