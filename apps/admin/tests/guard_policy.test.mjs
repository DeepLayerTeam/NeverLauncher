import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, sign, webcrypto} from 'node:crypto';
import { verifyGuardEnvelope05011, guardCandidate05011, guardCandidateAllowed05011 } from '../src/admin/guard_policy_offline_05011.ts';

test('Проверка Ed25519 в браузере для Guard выявляет изменения и обеспечивает безопасный откат', async () => {
 const {publicKey,privateKey}=generateKeyPairSync('ed25519');
 const keyHex=publicKey.export({type:'spki',format:'der'}).subarray(-32).toString('hex');
 const now=Math.floor(Date.now()/1000);
 const policy={schemaVersion:'launcher.guard-compatibility.v1',projectId:'project',minecraft:'1.21.1',loader:'fabric',epoch:9,issuedAt:now-10,expiresAt:now+3600,artifacts:[],transformations:[],revokedDigests:['c'.repeat(64)],revokedTransformations:['old-hook']};
 const envelope=(p)=>{const payload=Buffer.from(JSON.stringify(p));return JSON.stringify({schemaVersion:p.schemaVersion,payload:payload.toString('base64'),signature:sign(null,Buffer.concat([Buffer.from('Launcher-Guard-Compatibility-v1\n'),payload]),privateKey).toString('hex')})};
 const verified=await verifyGuardEnvelope05011(envelope(policy),keyHex);
 assert.equal(verified.epoch,9);
 await assert.rejects(()=>verifyGuardEnvelope05011(envelope({...policy,epoch:10}).replace(/signature[^,]*/, 'signature":"'+'0'.repeat(128)+'"'),keyHex));
 const previous={...policy,epoch:4,revokedDigests:[],revokedTransformations:[]};
 const rollback=guardCandidate05011(policy,previous,'a'.repeat(64),'new-hook',now);
 assert.equal(rollback.epoch,10);
 assert.ok(rollback.revokedDigests.includes('c'.repeat(64)));
 assert.ok(rollback.revokedTransforms===undefined);
 assert.ok(rollback.revokedTransformations.includes('old-hook'));
 assert.doesNotThrow(()=>guardCandidateAllowed05011(policy,rollback));
 assert.throws(()=>guardCandidateAllowed05011(policy,{...rollback,revokedDigests:[]}));
});
