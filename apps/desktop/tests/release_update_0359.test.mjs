import test from 'node:test';
import assert from 'node:assert/strict';
import {updateIdentity0359,approvedSelectionIdentity0393,ensureReleaseApproval0359} from '../build-tests/release_update_0359.js';
const manifest = {projectId:'demo',profileId:'fabric',channel:'stable',version:'14',signature:{signature:'a'.repeat(88)}};
const preview={installedVersion:'13',targetVersion:'14',targetSignature:manifest.signature.signature,changes:['Java 17 → Java 21'],proposedPreset:'base',blockers:[],requiresConfirmation:true};
test('a newer signed update cannot silently reuse approval from another signed target',()=>{
 const accepted=approvedSelectionIdentity0393(manifest,'base');
 assert.doesNotThrow(()=>ensureReleaseApproval0359(manifest,preview,accepted,'','base'));
 assert.throws(()=>ensureReleaseApproval0359(manifest,preview,'','', 'base'),/явного подтверждения/);
 assert.throws(()=>ensureReleaseApproval0359({...manifest,signature:{signature:'b'.repeat(88)}},preview,accepted,'','base'),/нативной проверки/);
 assert.throws(()=>ensureReleaseApproval0359({...manifest,profileId:'other'},preview,accepted,'','base'),/явного подтверждения/);
 assert.throws(()=>ensureReleaseApproval0359({...manifest,version:'15'},preview,accepted,'','base'),/нативной проверки/);
 assert.throws(()=>ensureReleaseApproval0359({...manifest,signature:{signature:'b'.repeat(88)}},{...preview,requiresConfirmation:false},''),/нативной проверки/);
});
test('blockers and unavailable previews fail closed',()=>{
 assert.throws(()=>ensureReleaseApproval0359(manifest,{...preview,blockers:['dependency conflict']},approvedSelectionIdentity0393(manifest,'base'),'','base'),/dependency conflict/);
 assert.throws(()=>ensureReleaseApproval0359(manifest,null,''),/нативной проверки/);
 assert.throws(()=>ensureReleaseApproval0359({...manifest,signature:undefined},preview,''),/подписи/);
 assert.throws(()=>ensureReleaseApproval0359(manifest,preview,'','failed native check'),/нативной проверки/);
});
test('unchanged installed release does not require repeated confirmation',()=>{
 assert.doesNotThrow(()=>ensureReleaseApproval0359(manifest,{...preview,requiresConfirmation:false},''));
});


test('approval is specific to the signed selected preset and cannot be replayed for another selection',()=>{
 const approved=approvedSelectionIdentity0393(manifest,'base');
 assert.doesNotThrow(()=>ensureReleaseApproval0359(manifest,preview,approved,'','base'));
 assert.throws(()=>ensureReleaseApproval0359(manifest,preview,approved,'','optifine'),/точного preset/);
 assert.throws(()=>ensureReleaseApproval0359(manifest,{...preview,proposedPreset:'optifine'},approved,'','base'),/точного preset/);
 assert.throws(()=>ensureReleaseApproval0359(manifest,preview,approvedSelectionIdentity0393({...manifest,channel:'beta'},'base'),'','base'),/точного preset/);
 assert.throws(()=>ensureReleaseApproval0359(manifest,{...preview,proposedPreset:null},approved,'','base'),/точного preset/);
 assert.doesNotThrow(()=>ensureReleaseApproval0359(manifest,{...preview,proposedPreset:null},approvedSelectionIdentity0393(manifest,''),'',''));
});
