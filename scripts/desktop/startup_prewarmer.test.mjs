import test from 'node:test';
import assert from 'node:assert/strict';
import {warmAfterIdle03011} from '../../apps/desktop/src/startup_prewarmer_03011.ts';
const flush = () => new Promise(resolve=>setImmediate(resolve));
test('Фоновый предварительный прогрев отложен и выполняется последовательно, не задерживая запуск', async()=>{
 let fire;const seen=[];let complete;
 const unblock=new Promise(resolve=>{complete=resolve});
 warmAfterIdle03011(work=>{fire=work;return ()=>{}},async name=>{seen.push(name);if(name==='official')await unblock},['official','components']);
 assert.deepEqual(seen,[]);
 fire();await flush();assert.deepEqual(seen,['official']);
 complete();await flush();assert.deepEqual(seen,['official','components']);
});
test('Отменённые фоновые задания не загружают данные заранее', async()=>{
 let fire, cancelled=false;const seen=[];
 const stop=warmAfterIdle03011(work=>{fire=work;return ()=>{cancelled=true}},async name=>{seen.push(name)},['official']);
 stop();fire();await flush();assert.equal(cancelled,true);assert.deepEqual(seen,[]);
});
test('Ошибка необязательной предварительной загрузки не блокирует следующие загрузки', async()=>{
 let fire;const seen=[];
 warmAfterIdle03011(work=>{fire=work;return ()=>{}},async name=>{seen.push(name);if(name==='first')throw Error('offline')},['first','second']);
 fire();await flush();assert.deepEqual(seen,['first','second']);
});

test('После начала запуска предварительный прогрев прекращает необязательные действия', async()=>{
 let fire, resume, running=false;
 const seen=[];
 const first=new Promise(resolve=>{resume=resolve});
 const stop=warmAfterIdle03011(work=>{fire=work;return ()=>{}},async name=>{seen.push(name);if(name==='official') await first},['official','components'],()=>!running);
 fire(); await flush();
 running=true; resume(); await flush();
 assert.deepEqual(seen,['official']);
 stop();
});
