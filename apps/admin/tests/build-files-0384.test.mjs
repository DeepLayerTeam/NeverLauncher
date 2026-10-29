import {test} from 'node:test';
import assert from 'node:assert/strict';
import {planImports0384,normalizeImportPath0384,diffCounts0384,hasCompleteBuild0384} from '../src/admin/build-files-0384.ts';

test('Directory import removes only the selected directory root, while a file picker retains names',()=>{
 const {accepted,skipped}=planImports0384([
  {name:'client.jar',webkitRelativePath:'ServerPack/mods/client.jar'},
  {name:'1.21.json',webkitRelativePath:'ServerPack/versions/1.21.json'},
  {name:'options.txt',webkitRelativePath:'ServerPack/options.txt'},
  {name:'level.dat',webkitRelativePath:'ServerPack/saves/world/level.dat'},
 ]);
 assert.deepEqual(accepted.map(x=>x.path),['mods/client.jar','versions/1.21.json']);
 assert.deepEqual(skipped,['options.txt','saves/world/level.dat']);
 assert.equal(normalizeImportPath0384({name:'root.jar'}),'root.jar');
});
test('Paths cannot traverse, contain Windows collisions, or introduce empty segments',()=>{
 for(const value of ['dir/../../escape.jar','dir//escape.jar','/absolute','C:/drive','mods/./fake.jar']){
  assert.throws(()=>normalizeImportPath0384({name:value}),/Недопустимый путь/);
 }
 assert.throws(()=>planImports0384([{name:'One.jar',webkitRelativePath:'Pack/mods/One.jar'},{name:'one.jar',webkitRelativePath:'Pack/mods/one.jar'}]),/Конфликт имён/);
});
test('Diff summary counts changes; materialized package requires exact paths, hash and size',()=>{
 assert.deepEqual(diffCounts0384([{path:'a',change:'added'},{path:'b',change:'modified'},{path:'c',change:'modified'}]),{added:1,modified:2});
 const inputs=[{path:'mods/a.jar',size:3,sha256:'abc',selected:true},{path:'mods/b.jar',size:5,sha256:'def',selected:false}];
 assert.equal(hasCompleteBuild0384(inputs,[{path:'mods/a.jar',size:3,sha256:'abc'}]),true);
 assert.equal(hasCompleteBuild0384(inputs,[{path:'mods/a.jar',size:4,sha256:'abc'}]),false);
 assert.equal(hasCompleteBuild0384(inputs,[{path:'mods/a.jar',size:3,sha256:'xyz'}]),false);
 assert.equal(hasCompleteBuild0384(inputs,[{path:'mods/a.jar',size:3,sha256:'abc'},{path:'mods/b.jar',size:5,sha256:'def'}]),false);
});
