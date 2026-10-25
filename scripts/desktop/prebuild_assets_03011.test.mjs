import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, mkdir, writeFile, symlink, rm, readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {packDist03011, verifyDist03011} from './prebuild_assets_03011.mjs';

async function fixture(run) {
  const root = await mkdtemp(join(tmpdir(), 'nl-asset-03011-'));
  try {
    await mkdir(join(root,'assets'));
    await writeFile(join(root,'index.html'), '<script type="module" src="/assets/index-12345678.js"></script>');
    await writeFile(join(root,'assets/index-12345678.js'), 'import("./login-abcdef01.js")');
    await writeFile(join(root,'assets/login-abcdef01.js'), 'export default 1;');
    return await run(root);
  } finally { await rm(root, {recursive:true, force:true}); }
}
test('real asset prebuild indexes hashed chunks and verifies installed bytes', async()=>fixture(async root=>{
  const first=await packDist03011(root);
  assert.equal(first.assets.length,3);
  assert.equal((await verifyDist03011(root)).assets.length,3);
  const serialized=await readFile(join(root,'asset-index-03011.json'),'utf8');
  await packDist03011(root);
  assert.equal(await readFile(join(root,'asset-index-03011.json'),'utf8'), serialized);
}));
test('modified or missing cached chunks are rejected', async()=>fixture(async root=>{
  await packDist03011(root);
  await writeFile(join(root,'assets/login-abcdef01.js'),'tampered');
  await assert.rejects(verifyDist03011(root),/corrupted/);
}));
test('symlinks, source maps and unhashed JS are rejected before release', async()=>fixture(async root=>{
  await writeFile(join(root,'assets/private.js.map'),'secret');
  await assert.rejects(packDist03011(root),/source map/);
  await rm(join(root,'assets/private.js.map'));
  await writeFile(join(root,'assets/app.js'),'old');
  await assert.rejects(packDist03011(root),/uncacheable/);
  await rm(join(root,'assets/app.js'));
  await symlink(join(root,'index.html'), join(root,'assets/alias-12345678.js'));
  await assert.rejects(packDist03011(root),/symlink/);
}));
test('Sentry release can prebuild before protected map upload but verify refuses to ship maps', async()=>fixture(async root=>{
  await writeFile(join(root,'assets/index-12345678.js.map'),'source map');
  const old=process.env.NEVERLAUNCHER_SENTRY_RELEASE_BUILD;
  process.env.NEVERLAUNCHER_SENTRY_RELEASE_BUILD='1';
  try { await packDist03011(root); } finally {
    if(old===undefined)delete process.env.NEVERLAUNCHER_SENTRY_RELEASE_BUILD;
    else process.env.NEVERLAUNCHER_SENTRY_RELEASE_BUILD=old;
  }
  await assert.rejects(verifyDist03011(root),/source map/);
  await rm(join(root,'assets/index-12345678.js.map'));
  await verifyDist03011(root);
}));
