import test from 'node:test';
import assert from 'node:assert/strict';
import {updateIdentity0359,approvedSelectionIdentity0393,ensureReleaseApproval0359} from '../build-tests/release_update_0359.js';
const manifest = {projectId:'demo',profileId:'fabric',channel:'stable',version:'14',signature:{signature:'a'.repeat(88)}};
const preview={installedVersion:'13',targetVersion:'14',targetSignature:manifest.signature.signature,changes:['Java 17 → Java 21'],proposedPreset:'base',blockers:[],requiresConfirmation:true};
test('Новое подписанное обновление не может незаметно использовать подтверждение от другой подписанной цели',()=>{
 const accepted=approvedSelectionIdentity0393(manifest,'base');
 assert.doesNotThrow(()=>ensureReleaseApproval0359(manifest,preview,accepted,'','base'));
 assert.throws(()=>ensureReleaseApproval0359(manifest,preview,'','', 'base'),/явного подтверждения/);
 assert.throws(()=>ensureReleaseApproval0359({...manifest,signature:{signature:'b'.repeat(88)}},preview,accepted,'','base'),/нативной проверки/);
 assert.throws(()=>ensureReleaseApproval0359({...manifest,profileId:'other'},preview,accepted,'','base'),/явного подтверждения/);
 assert.throws(()=>ensureReleaseApproval0359({...manifest,version:'15'},preview,accepted,'','base'),/нативной проверки/);
 assert.throws(()=>ensureReleaseApproval0359({...manifest,signature:{signature:'b'.repeat(88)}},{...preview,requiresConfirmation:false},''),/нативной проверки/);
});
test('Блокирующие условия и недоступные предварительные просмотры приводят к безопасному отказу',()=>{
 assert.throws(()=>ensureReleaseApproval0359(manifest,{...preview,blockers:['dependency conflict']},approvedSelectionIdentity0393(manifest,'base'),'','base'),/dependency conflict/);
 assert.throws(()=>ensureReleaseApproval0359(manifest,null,''),/нативной проверки/);
 assert.throws(()=>ensureReleaseApproval0359({...manifest,signature:undefined},preview,''),/подписи/);
 assert.throws(()=>ensureReleaseApproval0359(manifest,preview,'','failed native check'),/нативной проверки/);
});
test('Неизменённый установленный релиз не требует повторного подтверждения',()=>{
 assert.doesNotThrow(()=>ensureReleaseApproval0359(manifest,{...preview,requiresConfirmation:false},''));
});


test('Подтверждение привязано к выбранному подписанному набору настроек и не переносится на другой выбор',()=>{
 const approved=approvedSelectionIdentity0393(manifest,'base');
 assert.doesNotThrow(()=>ensureReleaseApproval0359(manifest,preview,approved,'','base'));
 assert.throws(()=>ensureReleaseApproval0359(manifest,preview,approved,'','optifine'),/точного preset/);
 assert.throws(()=>ensureReleaseApproval0359(manifest,{...preview,proposedPreset:'optifine'},approved,'','base'),/точного preset/);
 assert.throws(()=>ensureReleaseApproval0359(manifest,preview,approvedSelectionIdentity0393({...manifest,channel:'beta'},'base'),'','base'),/точного preset/);
 assert.throws(()=>ensureReleaseApproval0359(manifest,{...preview,proposedPreset:null},approved,'','base'),/точного preset/);
 assert.doesNotThrow(()=>ensureReleaseApproval0359(manifest,{...preview,proposedPreset:null},approvedSelectionIdentity0393(manifest,''),'',''));
});
