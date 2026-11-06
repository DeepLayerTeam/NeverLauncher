import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveLaunchMode0269 } from '../build-tests/launch_modes_0269.js';
import { launchPreferences } from '../build-tests/desktop_experience_0229.js';

const intent = {identity:'official',hasOfficialProfile:true,offlineAllowed:false,autoEnter:true,serverId:''};
test('Официальный режим подключается напрямую без сеанса ServerBridge',()=>{
  assert.equal(resolveLaunchMode0269(intent),'official');
  assert.throws(()=>resolveLaunchMode0269({...intent,serverId:'bridge-one'}),/ServerBridge/);
  assert.throws(()=>resolveLaunchMode0269({...intent,hasOfficialProfile:false}),/официальный/);
});
test('Yggdrasil не зависит от официальной учётной записи',()=>{
  assert.equal(resolveLaunchMode0269({...intent,identity:'local',hasOfficialProfile:false,serverId:'bridge-one'}),'local');
  assert.throws(()=>resolveLaunchMode0269({...intent,identity:'invalid'}),/Неизвестный/);
});
test('Автономный режим требует подписанного разрешения релиза и запрещает автоподключение',()=>{
  assert.throws(()=>resolveLaunchMode0269({...intent,identity:'offline'}),/подписанным/);
  assert.throws(()=>resolveLaunchMode0269({...intent,identity:'offline',offlineAllowed:true}),/Offline не подключается/);
  assert.equal(resolveLaunchMode0269({...intent,identity:'offline',offlineAllowed:true,autoEnter:false}),'offline');
});
const settings={memoryMb:4096,screenWidth:1280,screenHeight:720,fullscreen:false,autoEnter:true,serverHost:'mc.example.org',serverPort:25565,serverId:'',offlineEnabled:false};
test('Автоматическое прямое подключение к серверу Minecraft включается только в явно выбранном официальном режиме',()=>{
  assert.throws(()=>launchPreferences(settings,{minimumMb:512,maximumMb:8192},false,[]),/Выберите доступный сервер/);
  const prefs=launchPreferences(settings,{minimumMb:512,maximumMb:8192},false,[],false,true);
  assert.equal(prefs.autoEnter,true);
  assert.equal(prefs.serverHost,'mc.example.org');
  assert.equal(prefs.offline,false);
});
