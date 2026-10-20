// `node --test` after transpiling the pure selection module with tsc.
import test from 'node:test';
import assert from 'node:assert/strict';
import {parseChoice0247,encodeChoice0247,proposeChoice0247} from '../build-tests/component_selection_0247.js';
test('stable canonical choices and duplicate rejection',()=>{
  assert.equal(encodeChoice0247(parseChoice0247('@custom:v1:quality:+iris,-optifine')),'@custom:v1:quality:+iris,-optifine');
  assert.throws(()=>parseChoice0247('@custom:v1::+a,+a'),/повторная/);
  assert.throws(()=>parseChoice0247('@custom:v1::+unknown/evil'),/Некорректная/);
});
test('selecting incompatible mod cascades out dependents',()=>{
  const cat=[{id:'iris',name:'Iris',dependencies:[{id:'sodium'}]},{id:'sodium',name:'Sodium',conflicts:[{id:'optifine'}]},{id:'optifine',name:'OptiFine'}];
  const choice=proposeChoice0247('',cat,['iris','sodium'],'optifine',true);
  assert.deepEqual(choice.removed,['iris','sodium']);
  assert.deepEqual(choice.added,['optifine']);
});
test('required removal refused',()=>{
  assert.throws(()=>proposeChoice0247('',[{id:'core',name:'core',required:true}],['core'],'core',false),/нельзя/);
});
