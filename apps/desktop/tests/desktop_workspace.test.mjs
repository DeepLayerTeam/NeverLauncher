import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';
const requireNode=createRequire(import.meta.url);
const ts=requireNode('typescript');
const source=readFileSync(new URL('../src/DesktopWorkspace0353.tsx',import.meta.url),'utf8');
const output=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS,jsx:ts.JsxEmit.React,esModuleInterop:true},reportDiagnostics:true});
assert.equal(output.diagnostics?.filter(d=>d.category===ts.DiagnosticCategory.Error).length,0);
const React={createElement:(type,props,...children)=>({type,props:props||{},children:children.flat()}),useState:(value)=>[value,()=>{}],useMemo:(fn)=>fn()};
const navigationSource=readFileSync(new URL('../src/desktop_navigation_0353.ts',import.meta.url),'utf8');
const navigationCode=ts.transpileModule(navigationSource,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS}}).outputText;
const navigationModule={exports:{}};
runInNewContext(navigationCode,{module:navigationModule,exports:navigationModule.exports});
const module={exports:{}};
runInNewContext(output.outputText,{module,exports:module.exports,require:(name)=>{
  if(name==='react')return React;
  if(name==='./desktop_navigation_0353')return navigationModule.exports;
  throw Error(`Unexpected dependency ${name}`);
}});
const {BuildsWorkspace0353,ServersWorkspace0353,HistoryWorkspace0353}=module.exports;
function flatten(element){if(element==null||typeof element!=='object')return [];
 return [element,...(element.children||[]).flatMap(flatten)];}
function buttons(tree){return flatten(tree).filter(node=>node.type==='button');}
function label(node){return JSON.stringify(node.children.map(x=>typeof x==='string'?x:x?.children||[]));}
function buttonWith(tree,s){const match=buttons(tree).find(b=>label(b).includes(s));assert.ok(match,`No button for ${s}`);return match;}
test('build catalog buttons execute selected project/profile operations and navigation',()=>{
 const events=[];
 const tree=BuildsWorkspace0353({projects:[{id:'p',title:'Example'}],profiles:[{id:'client',name:'Client'}],selectedProject:'p',selectedProfile:'client',manifest:{projectId:'p',profileId:'client',version:'v1',channel:'stable',minecraft:{version:'1.20',loader:'Fabric'},files:[{path:'a'}]},signedProject:'',signedProfile:'',loading:false,error:'',refresh:()=>events.push('reload'),chooseProject:id=>events.push(`project:${id}`),chooseProfile:id=>events.push(`profile:${id}`),showMods:()=>events.push('mods'),showDownloads:()=>events.push('downloads')});
 buttonWith(tree,'Example').props.onClick();buttonWith(tree,'Client').props.onClick();
 buttonWith(tree,'Выбрать моды').props.onClick();buttonWith(tree,'Установка / проверка').props.onClick();
 assert.deepEqual(events,['project:p','profile:client','mods','downloads']);
});
test('signed workspace cannot choose another project/profile',()=>{
 const tree=BuildsWorkspace0353({projects:[{id:'owner'},{id:'other'}],profiles:[{id:'fixed'},{id:'other-profile'}],selectedProject:'owner',selectedProfile:'fixed',manifest:null,signedProject:'owner',signedProfile:'fixed',loading:false,error:'',refresh:()=>{},chooseProject:()=>{},chooseProfile:()=>{},showMods:()=>{},showDownloads:()=>{}});
 assert.equal(buttonWith(tree,'other').props.disabled,true);
 assert.equal(buttonWith(tree,'other-profile').props.disabled,true);
});
test('server browser dispatches only active server, uses native-persist callback',async()=>{
 const events=[];
 const tree=ServersWorkspace0353({servers:[{id:'a',name:'Alpha',kind:'Paper',health:'healthy',status:'active'}, {id:'b',name:'Beta',kind:'Paper',health:'down',status:'revoked'}],selectedId:'a',signedId:'',autoEnter:false,serverHost:'',serverPort:25565,offline:false,projectId:'p',profileId:'x',error:'',loading:false,reload:()=>events.push('reload'),select:id=>events.push(`select:${id}`),save:async()=>{events.push('save')},onOpenSettings:()=>events.push('settings')});
 assert.equal(buttonWith(tree,'Beta').props.disabled,true);
 buttonWith(tree,'Alpha').props.onClick();await buttonWith(tree,'Сохранить выбор').props.onClick();
 assert.deepEqual(events,['select:a','save']);
});
test('history exposes native entries, filters and invokes actual refresh/stop callbacks',()=>{
 const events=[];
 const tree=HistoryWorkspace0353({entries:[{startedAt:'2026-10-28T01:00:00Z',success:false,projectId:'p',profileId:'main',version:'1',message:'crashed',logPath:'/logs/mc.log'}],loading:false,error:'',reload:()=>events.push('reload'),activeProcess:{id:'pid',state:'running',message:'running'},onStop:()=>events.push('stop')});
 buttonWith(tree,'Обновить историю').props.onClick();buttonWith(tree,'Остановить Minecraft').props.onClick();
 assert.deepEqual(events,['reload','stop']);
 assert.ok(buttonWith(tree,'main'));
});
