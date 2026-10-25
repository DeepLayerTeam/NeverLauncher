import test from 'node:test';
import assert from 'node:assert/strict';
import {stackFrames0309, installErrorCapture0309} from '../build-tests/sentry_diagnostics_0309.js';
test('sourcemap frames are limited to packaged assets',()=>{
 const out=stackFrames0309('Error: bearer secret\n at https://host/assets/index-a1b2.js:120:3\n at file:///home/john/private.js:3:9');
 assert.deepEqual(out,[{asset:'assets/index-a1b2.js',line:120,column:3}]);
 assert.deepEqual(stackFrames0309('file:///Users/user/token.js:5:5'),[]);
});
test('reporters receive no exception message or untrusted URLs',()=>{
 const handlers=new Map(),sent=[];
 const target={addEventListener:(name,cb)=>handlers.set(name,cb),removeEventListener:(name)=>handlers.delete(name)};
 const dispose=installErrorCapture0309(target,(category,frames)=>sent.push({category,frames}));
 handlers.get('error')({error:new Error('Bearer private-secret')});
 handlers.get('unhandledrejection')({reason:new Error('password=123')});
 assert.deepEqual(sent.map(x=>x.category),['desktop.js.uncaught','desktop.js.rejection']);
 assert.equal(JSON.stringify(sent).includes('private-secret'),false);
 dispose();assert.equal(handlers.size,0);
});
