import { test } from 'node:test';
import assert from 'node:assert/strict';
import { launchPreferences, scopedServers } from '../src/desktop_experience_0229.ts';
const settings = { memoryMb: 4096, screenWidth: 1280, screenHeight: 720, fullscreen: false, autoEnter: false, serverHost: '', serverPort: 25565, offlineEnabled: false, serverId: '' };
const server = [{ id:'pvp', name:'PVP',kind:'velocity',status:'active',health:'unknown' }];
test('blocks out-of-range memory and resolution', () => {
 assert.throws(() => launchPreferences({...settings,memoryMb:8192}, {minimumMb:2048,maximumMb:4096}, false, server),/RAM/);
 assert.throws(() => launchPreferences({...settings,screenWidth:0}, {}, false, server),/resolution/);
});
test('offline requires explicit signed policy and cannot auto-enter', () => {
 assert.throws(() => launchPreferences({...settings,offlineEnabled:true}, {}, false, server),/Offline/);
 assert.throws(() => launchPreferences({...settings,offlineEnabled:true,autoEnter:true}, {}, true, server),/mutually exclusive/);
 assert.equal(launchPreferences({...settings,offlineEnabled:true}, {}, true, server).offline, true);
});
test('auto-enter requires an available node and explicit public host', () => {
 assert.throws(() => launchPreferences({...settings,autoEnter:true,serverId:'other'}, {}, false, server),/available/);
 assert.throws(() => launchPreferences({...settings,autoEnter:true,serverId:'pvp',serverHost:'bad/host'}, {}, false, server),/address/);
 const p=launchPreferences({...settings,autoEnter:true,serverId:'pvp',serverHost:'mc.example.test'}, {}, false, server);
 assert.equal(p.serverHost, 'mc.example.test');
});
test('catalog rejects inactive nodes and repeated ids', () => {
 const result=scopedServers({items:[...server, {...server[0],name:'duplicated'},{...server[0],id:'dead',status:'revoked'}]});
 assert.equal(result.length,1);
});
