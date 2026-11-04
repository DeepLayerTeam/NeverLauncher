import test from 'node:test';
import assert from 'node:assert/strict';
import {selectLocale0357,validateUISettings0357,nextZoom0357,shortcut0357,rovingNav0357,canNavigate0357,SCREENS0357,STRINGS0357} from '../build-tests/desktop_accessibility_0357.js';
test('preferences reject injection, malformed values and out-of-policy zoom',()=>{
 assert.deepEqual(validateUISettings0357({locale:'<script>',zoom:999,reducedMotion:'false',highContrast:1},'en'), {locale:'en',zoom:100,reducedMotion:false,highContrast:false});
 assert.equal(selectLocale0357('de'),'ru');
 assert.equal(validateUISettings0357({locale:'ru',zoom:125,reducedMotion:true,highContrast:true}).zoom,125);
});
test('zoom clamps and normalizes',()=>{
 assert.equal(nextZoom0357(200,1),200); assert.equal(nextZoom0357(80,-1),80);
 assert.equal(nextZoom0357(125,0),100); assert.equal(nextZoom0357(100,1),110); assert.equal(nextZoom0357(100,-1),90);
});
test('OS modifier behavior, IME and editable controls are respected',()=>{
 const e={key:'+',ctrlKey:true,metaKey:false,altKey:false,shiftKey:true,target:null};
 assert.deepEqual(shortcut0357(e,'windows'),{type:'zoom',direction:1});
 assert.equal(shortcut0357(e,'macos'),null);
 assert.deepEqual(shortcut0357({...e,ctrlKey:false,metaKey:true},'macos'),{type:'zoom',direction:1});
 assert.equal(shortcut0357({...e,isComposing:true},'windows'),null);
 assert.equal(shortcut0357({...e,target:{tagName:'TEXTAREA',isContentEditable:false}},'windows'),null);
 assert.deepEqual(shortcut0357({...e,key:'4',shiftKey:false},'windows'),{type:'section',index:3});
 assert.equal(shortcut0357({...e,key:'9',shiftKey:false,altKey:true},'windows'),null);
 assert.deepEqual(shortcut0357({...e,key:'F6',ctrlKey:false,shiftKey:false},'windows'),{type:'focusNav'});
 assert.deepEqual(shortcut0357({...e,key:'F6',ctrlKey:false,shiftKey:false,target:{tagName:'INPUT'}},'windows'),{type:'focusNav'});
});
test('arrow navigation wraps and Home/End choose endpoints',()=>{
 assert.equal(rovingNav0357('ArrowDown',11,12),0); assert.equal(rovingNav0357('ArrowUp',0,12),11);
 assert.equal(rovingNav0357('Home',5,12),0); assert.equal(rovingNav0357('End',5,12),11);
 assert.equal(rovingNav0357('Enter',3,12),null);
});
test('navigation is translated for every screen in both languages',()=>{
 assert.equal(SCREENS0357.length,12);
 for (const lang of ['ru','en']) {
  assert.equal(STRINGS0357[lang].sections.length,SCREENS0357.length);
  assert.ok(STRINGS0357[lang].sections.every(s=>s.length));
 }
});

test('all screen shortcuts fail closed until verified native configuration and signed first-run',()=>{
 for(const screen of SCREENS0357){
  assert.equal(canNavigate0357(screen,false,false,false,false),screen==='firstRun');
  assert.equal(canNavigate0357(screen,true,true,false,false),screen==='firstRun');
  assert.equal(canNavigate0357(screen,true,false,true,false),screen==='firstRun'||screen==='auth');
  assert.equal(canNavigate0357(screen,true,false,true,true),true);
 }
});

test('all translated core actions have matching nonempty keys',()=>{
 const ru=STRINGS0357.ru,en=STRINGS0357.en;
 const ruKeys=Object.keys(ru).sort(),enKeys=Object.keys(en).sort();
 assert.deepEqual(ruKeys,enKeys);
 for (const key of ruKeys){
  const valueRu=ru[key], valueEn=en[key];
  if(Array.isArray(valueRu)) {assert.equal(valueRu.length,valueEn.length);assert.ok(valueEn.every(item=>item.length>0));}
  else {assert.ok(valueRu.length>0 && valueEn.length>0,key);}
 }
});
