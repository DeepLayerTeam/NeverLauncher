// A real cross-language SDK probe, not a fetch() imitation of the client.
import { NeverLauncherAPI } from '../dist/client.js';
import { createHash } from 'node:crypto';
const need = (name) => {const v = process.env[name]; if (!v) throw new Error(`missing live SDK setting ${name}`); return v;};
try {
 const api = new NeverLauncherAPI(need('NL_GA_ORIGIN'), need('NL_GA_BEARER'));
 await api.checkCompatibility();
 const body = await api.request('GET',need('NL_GA_JSON_PATH'));
 if (!body || typeof body !== 'object' || !Object.keys(body).length) throw new Error('empty live JSON');
 const text = await api.request('GET',need('NL_GA_TEXT_PATH'),{responseType:'text'});
 if (typeof text !== 'string' || text.length < 10 || text.includes('\0')) throw new Error('real text response missing');
 const stream = await api.request('GET',need('NL_GA_BINARY_PATH'),{responseType:'stream'});
 const hash = createHash('sha256'); let size=0;
 for await (const chunk of stream) { size += chunk.byteLength; hash.update(chunk); }
 if (size < 8 || hash.digest('hex') !== need('NL_GA_BINARY_SHA256')) throw new Error('binary SDK streaming changed bytes');
 await api.request('GET','https://untrusted.invalid').then(() => {throw new Error('unsafe route accepted');},()=>{});
 console.log(`PASS sdk=typescript checks=3 binaryBytes=${size} binarySha256=${process.env.NL_GA_BINARY_SHA256}`);
} catch (error) { console.error('BLOCKED SDK TypeScript: '+error.constructor.name); process.exitCode=2; }
