#!/usr/bin/env node
// Post-Vite deterministic integrity index of real, hashed distribution assets.
// No inline secrets, absolute filesystem paths or development source maps ship.
import {readdir, lstat, readFile, writeFile, rename} from 'node:fs/promises';
import {resolve, relative, join} from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
const INDEX = 'asset-index-03011.json';
const hashed = /-[a-zA-Z0-9_-]{8,}\.(?:js|css)$/;
const allowed = /\.(?:js|css|html|svg|png|webp|ico|woff2?)$/;
const sha = b => createHash('sha256').update(b).digest('hex');

export async function scanDist03011(dist, allowSentryMaps = false) {
  const base = resolve(dist);
  const entries = [];
  async function visit(dir) {
    for (const entry of (await readdir(dir)).sort()) {
      const name = join(dir, entry);
      const stat = await lstat(name);
      if (stat.isSymbolicLink()) throw Error(`symlink in distribution: ${entry}`);
      if (stat.isDirectory()) { await visit(name); continue; }
      if (!stat.isFile()) throw Error(`non-file in distribution: ${entry}`);
      const path = relative(base, name).split('\\').join('/');
      if (path === INDEX) continue;
      if (/\.map$/i.test(path)) { if (!allowSentryMaps) throw Error(`source map must be uploaded to Sentry, not shipped: ${path}`); continue; }
      if (!allowed.test(path)) throw Error(`unexpected distributable asset: ${path}`);
      const data = await readFile(name);
      if (!data.length) throw Error(`empty asset: ${path}`);
      if (path.startsWith('assets/') && !hashed.test(path) && /\.(js|css)$/.test(path)) throw Error(`uncacheable asset filename: ${path}`);
      entries.push({path, size:data.length, sha256:sha(data)});
    }
  }
  await visit(base);
  if (!entries.some(e => e.path === 'index.html') || !entries.some(e => e.path.endsWith('.js')))
    throw Error('missing index.html or Vite JS build output');
  return {schemaVersion:'1.0', product:'NeverLauncher Desktop', assets:entries.sort((a,b)=>a.path < b.path ? -1 : a.path > b.path ? 1 : 0)};
}
export async function packDist03011(dist) {
  const manifest = await scanDist03011(dist, process.env.NEVERLAUNCHER_SENTRY_RELEASE_BUILD === '1');
  const target = join(resolve(dist), INDEX);
  const tmp = target + `.tmp-${process.pid}`;
  try { await writeFile(tmp, JSON.stringify(manifest, null, 2) + '\n', {flag:'wx'}); await rename(tmp,target); }
  catch(e) { const {rm} = await import('node:fs/promises'); await rm(tmp,{force:true}); throw e; }
  return manifest;
}
export async function verifyDist03011(dist) {
  const manifest = JSON.parse(await readFile(join(resolve(dist), INDEX), 'utf8'));
  const actual = await scanDist03011(dist);
  if (JSON.stringify(manifest) !== JSON.stringify(actual)) throw Error('desktop prebuilt assets corrupted, missing or stale');
  return actual;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [command, option, path] = process.argv.slice(2);
  if (!['pack','verify'].includes(command) || option !== '--dist' || !path) {
    console.error('usage: node prebuild_assets_03011.mjs pack|verify --dist <vite-dist>');
    process.exitCode = 2;
  } else {
    try { const result = command === 'pack' ? await packDist03011(path) : await verifyDist03011(path);
      console.log(`${command}: ${result.assets.length} verified build assets`); }
    catch (err) { console.error(String(err)); process.exitCode = 1; }
  }
}
