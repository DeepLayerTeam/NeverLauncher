import test from 'node:test';
import assert from 'node:assert/strict';
import {offlineLaunchSettings0358,offlineSelection0358,offlineRecovery0358} from '../build-tests/offline_policy.js';
const s={memoryMb:4096,screenWidth:1280,screenHeight:720,fullscreen:false,autoEnter:true,serverId:'protected-bridge',serverHost:'mc.example.com',serverPort:25565,offlineEnabled:false};
test('Автономный режим отключает подписанное автоподключение, не меняя действующую сетевую конфигурацию',()=>{
 const offline=offlineLaunchSettings0358(s,true);
 assert.equal(offline.offlineEnabled,true);
 assert.equal(offline.autoEnter,false);
 assert.equal(offline.serverId,'');
 assert.equal(offline.serverHost,'');
 assert.equal(offline.serverPort,25565);
 assert.equal(s.serverId,'protected-bridge');
 assert.equal(s.autoEnter,true);
});
test('Сетевой режим сохраняет настройки ServerBridge',()=>{
 assert.equal(offlineLaunchSettings0358(s,false),s);
 assert.deepEqual(offlineSelection0358('local',s),{offline:false,serverId:'protected-bridge',autoEnter:true});
 assert.deepEqual(offlineSelection0358('offline',s),{offline:true,serverId:'',autoEnter:false});
});
test('Ошибки автономного режима предлагают конкретное действие для восстановления',()=>{
 assert.match(offlineRecovery0358('offline denied: a signed owner bundle is required'),/подписанный пакет/);
 assert.match(offlineRecovery0358('offline denied: foo.jar (invalid) is not verified'),/Восстановить файлы/);
 assert.match(offlineRecovery0358('no cached manifest'),/кеш/);
 assert.match(offlineRecovery0358('offline cache disabled by signed profile policy'),/запрещает автономный режим/);
 assert.match(offlineRecovery0358('Ed25519 signature verification failed'),/подписанный пакет/);
});
