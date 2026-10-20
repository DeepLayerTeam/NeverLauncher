import {test} from 'node:test';
import assert from 'node:assert/strict';
import {freshComponent0248,listAvailableFiles0248,lintCatalog0248,parseRelations0248,formatRelations0248,renameComponent0248,removeComponent0248} from '../src/admin/component-editor-model-0248.ts';
const mk=()=>({schemaVersion:'5.0',revision:2,digest:'0'.repeat(64),components:[
 {...freshComponent0248('core',['mods/core.jar']),required:true},
 {...freshComponent0248('shaders',['mods/shaders.jar']),dependencies:[{id:'core',versionRange:'^1.0.0'}],conflicts:[{id:'core-opt'}]},
 {...freshComponent0248('core-opt',['mods/core-opt.jar'])}],presets:[{id:'quality',name:'Quality',components:['shaders','core']}],defaultPreset:'quality'});
const files=['mods/core.jar','mods/shaders.jar','mods/core-opt.jar'].map(path=>({path,ownership:'optional',size:10,sha256:'a'.repeat(64)}));
test('admin component rename keeps graph and preset stable references',()=>{
 const changed=renameComponent0248(mk(),'core','core-new');
 assert.deepEqual(changed.components[1].dependencies,[{id:'core-new',versionRange:'^1.0.0'}]);
 assert.deepEqual(changed.presets[0].components,['shaders','core-new']);
 assert.equal(lintCatalog0248(changed,files).length,0);
});
test('unlinking components does not strand dependencies or preset IDs',()=>{
 const changed=removeComponent0248(mk(),'core');
 assert.deepEqual(changed.components[0].dependencies,[]);
 assert.deepEqual(changed.presets[0].components,['shaders']);
 assert.equal(listAvailableFiles0248(changed,files,'shaders').some(f=>f.path==='mods/core.jar'),true);
});
test('local validation rejects orphaned ownership and multi-owner paths',()=>{
 const c=mk();c.components[2].files=['mods/core.jar'];
 const errors=lintCatalog0248(c,files);
 assert.ok(errors.some(e=>e.includes('нескольким')));
 assert.ok(errors.some(e=>e.includes('не назначен')));
});
test('relation parser handles version ranges and preserves exact input',()=>{
 const input='core >=1.0.0 <2.0.0\nshaders ^1.2.3';
 assert.equal(formatRelations0248(parseRelations0248(input)),input);
});
