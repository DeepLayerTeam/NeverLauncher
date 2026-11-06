import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {validateProfile0382} from '../src/admin/profile-launch-0382.ts';

const vanilla={id:'survival',name:'Survival',minecraftVersion:'1.21.1',loader:'vanilla',loaderVersion:'',javaMajor:21};
test('Редактор профиля проверяет полный профиль Vanilla',()=>{
  assert.equal(validateProfile0382(vanilla),'');
  assert.match(validateProfile0382({...vanilla,minecraftVersion:''}),/Minecraft/);
  assert.match(validateProfile0382({...vanilla,javaMajor:0}),/Java/);
});
test('Профиль с модами требует точной закреплённой версии загрузчика',()=>{
  assert.match(validateProfile0382({...vanilla,loader:'fabric'}),/точную версию/);
  assert.equal(validateProfile0382({...vanilla,loader:'fabric',loaderVersion:'0.16.14'}),'');
  assert.match(validateProfile0382({...vanilla,loaderVersion:'0.16.14'}),/Vanilla/);
  assert.match(validateProfile0382({...vanilla,loader:'custom',loaderVersion:'1.0'}),/Неподдерживаемый/);
});
test('Поля ID профиля и версии отклоняют пути и переводы строк',()=>{
  assert.match(validateProfile0382({...vanilla,id:'../escape'}),/ID/);
  assert.match(validateProfile0382({...vanilla,minecraftVersion:'1.21.1\nlatest'}),/Minecraft/);
  assert.match(validateProfile0382({...vanilla,loader:'forge',loaderVersion:'latest build'}),/точную версию/);
});
test('Рабочий экран сохраняет изменения с expectedRevision и использует реальный ответ сохранения',()=>{
  const editor=readFileSync(new URL('../src/admin/ProfileEditor0382.tsx',import.meta.url),'utf8');
  assert.match(editor,/expectedRevision:baseRevision/);
  assert.match(editor,/result\.profile\?\.id/);
  assert.match(editor,/\/revisions/);
  assert.match(editor,/window\.confirm/);
});
