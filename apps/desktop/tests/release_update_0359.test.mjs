import test from 'node:test';
import assert from 'node:assert/strict';
import {updateIdentity0359,ensureReleaseApproval0359} from '../build-tests/release_update_0359.js';
const manifest = {projectId:'demo',profileId:'fabric',channel:'stable',version:'14',signature:{signature:'a'.repeat(88)}};
const preview={installedVersion:'13',targetVersion:'14',targetSignature:manifest.signature.signature,changes:['Java 17 → Java 21'],proposedPreset:'base',blockers:[],requiresConfirmation:true};
test('a newer signed update cannot silently reuse approval from another signed target',()=>{
 const accepted=updateIdentity0359(manifest);
 assert.doesNotThrow(()=>ensureReleaseApproval0359(manifest,preview,accepted));
 assert.throws(()=>ensureReleaseApproval0359(manifest,preview,''),/явного подтверждения/);
 assert.throws(()=>ensureReleaseApproval0359({...manifest,signature:{signature:'b'.repeat(88)}},preview,accepted),/нативной проверки/);
 assert.throws(()=>ensureReleaseApproval0359({...manifest,profileId:'other'},preview,accepted),/явного подтверждения/);
 assert.throws(()=>ensureReleaseApproval0359({...manifest,version:'15'},preview,accepted),/нативной проверки/);
 assert.throws(()=>ensureReleaseApproval0359({...manifest,signature:{signature:'b'.repeat(88)}},{...preview,requiresConfirmation:false},''),/нативной проверки/);
});
test('blockers and unavailable previews fail closed',()=>{
 assert.throws(()=>ensureReleaseApproval0359(manifest,{...preview,blockers:['dependency conflict']},updateIdentity0359(manifest)),/dependency conflict/);
 assert.throws(()=>ensureReleaseApproval0359(manifest,null,''),/нативной проверки/);
 assert.throws(()=>ensureReleaseApproval0359({...manifest,signature:undefined},preview,''),/подписи/);
 assert.throws(()=>ensureReleaseApproval0359(manifest,preview,'','failed native check'),/нативной проверки/);
});
test('unchanged installed release does not require repeated confirmation',()=>{
 assert.doesNotThrow(()=>ensureReleaseApproval0359(manifest,{...preview,requiresConfirmation:false},''));
});
