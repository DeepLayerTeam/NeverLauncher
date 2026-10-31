/** Owner-side signing. Private Ed25519 seeds cross the network or storage. */
export type News0355 = { title: string; url: string };
export type Branding0355 = {
  displayName: string;
  publisher: string;
  websiteUrl?: string;
  accentColor?: string;
  backgroundColor?: string;
  textColor?: string;
  logoPng?: string;
  iconPng?: string;
  splashPng?: string;
  locale?: "ru" | "en";
  news?: News0355[];
};
type Bootstrap0355 = {
  schemaVersion: string;
  projectId: string;
  profileId: string;
  profilePublicKey: string;
  branding?: Branding0355;
  [key: string]: unknown;
};
type Envelope0355 = {
  schemaVersion: string;
  payload: string;
  signature: string;
  keyId?: string;
  trustEpoch?: number;
  signedAt?: string;
};
type TrustKey0355 = {
  id: string;
  role: string;
  publicKey: string;
  status: string;
  notBefore: string;
};
type Policy0355 = {
  schemaVersion: string;
  domain: string;
  epoch: number;
  issuedAt: string;
  expiresAt: string;
  keys: TrustKey0355[];
};
const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });
const pngHeader = [137, 80, 78, 71, 13, 10, 26, 10];
function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}
function parse<T>(s: string): T {
  return JSON.parse(s) as T;
}
function bytes(s: string): Uint8Array {
  return enc.encode(s);
}
function hex(raw: string, n: number): Uint8Array {
  assert(
    new RegExp(`^[a-fA-F0-9]{${n * 2}}$`).test(raw),
    `Ожидается ${n}-байтовый Ed25519 hex`,
  );
  return Uint8Array.from(raw.match(/../g)!, (part) =>
    Number.parseInt(part, 16),
  );
}
function hexString(raw: Uint8Array): string {
  return [...raw].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function base64Decode(raw: string): Uint8Array {
  assert(
    raw.length % 4 === 0 &&
      /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
        raw,
      ),
    "Некорректная base64",
  );
  return Uint8Array.from(atob(raw), (c) => c.charCodeAt(0));
}
function base64Encode(raw: Uint8Array): string {
  let s = "";
  for (let i = 0; i < raw.length; i += 8192)
    s += String.fromCharCode(...raw.subarray(i, i + 8192));
  return btoa(s);
}
function buffer(raw: Uint8Array): ArrayBuffer {
  return Uint8Array.from(raw).buffer;
}
async function verify(
  pub: string,
  message: Uint8Array,
  sig: string,
): Promise<void> {
  const key = await crypto.subtle.importKey(
    "raw",
    buffer(hex(pub, 32)),
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  assert(
    await crypto.subtle.verify(
      "Ed25519",
      key,
      buffer(hex(sig, 64)),
      buffer(message),
    ),
    "Ed25519: подпись не соответствует доверенному ключу",
  );
}
function https(raw: string): boolean {
  try {
    const u = new URL(raw);
    return (
      raw.length <= 2048 &&
      raw.startsWith("https://") &&
      u.protocol === "https:" &&
      !!u.hostname &&
      !u.username &&
      !u.password &&
      !u.hash &&
      !/[\s\\]/.test(raw)
    );
  } catch {
    return false;
  }
}
function image(
  raw: string | undefined,
  maxWidth = 1024,
  maxHeight = 1024,
): void {
  if (!raw) return;
  assert(raw.length <= 174764, "PNG превышает 128 KiB");
  const decoded = base64Decode(raw);
  assert(
    decoded.length >= 24 &&
      decoded.length <= 131072 &&
      pngHeader.every((c, i) => decoded[i] === c) &&
      dec.decode(decoded.subarray(12, 16)) === "IHDR",
    "Только встроенные PNG, без SVG/HTML и удалённых изображений",
  );
  const view = new DataView(
    decoded.buffer,
    decoded.byteOffset,
    decoded.byteLength,
  );
  assert(
    view.getUint32(8) === 13 &&
      view.getUint32(16) > 0 &&
      view.getUint32(16) <= maxWidth &&
      view.getUint32(20) > 0 &&
      view.getUint32(20) <= maxHeight,
    "Недопустимые размеры PNG",
  );
}
export function validateBrand0355(input: Branding0355): Branding0355 {
  assert(input && typeof input === "object", "Оформление отсутствует");
  assert(
    typeof input.displayName === "string" &&
      input.displayName.length > 0 &&
      input.displayName.length <= 80 &&
      typeof input.publisher === "string" &&
      input.publisher.length > 0 &&
      input.publisher.length <= 96 &&
      !/[\x00-\x1f\x7f]/.test(input.displayName + input.publisher),
    "Проверьте название и издателя",
  );
  if (input.websiteUrl)
    assert(https(input.websiteUrl), "Сайт бренда должен использовать HTTPS");
  for (const c of [input.accentColor, input.backgroundColor, input.textColor])
    if (c) assert(/^#[0-9a-fA-F]{6}$/.test(c), "Цвет должен быть #RRGGBB");
  assert(
    !input.locale || ["ru", "en"].includes(input.locale),
    "Поддерживаются ru и en",
  );
  image(input.logoPng);
  image(input.iconPng);
  image(input.splashPng, 2048, 1200);
  assert(
    !input.news || (Array.isArray(input.news) && input.news.length <= 5),
    "Допускается не более 5 новостей",
  );
  for (const n of input.news || [])
    assert(
      typeof n.title === "string" &&
        n.title.length > 0 &&
        n.title.length <= 120 &&
        !/[\x00-\x1f\x7f]/.test(n.title) &&
        typeof n.url === "string" &&
        https(n.url),
      "Некорректная ссылка новости",
    );
  return input;
}
async function policy0355(
  policyText: string,
  root: string,
): Promise<Policy0355> {
  assert(bytes(policyText).length <= 128 * 1024, "Trust policy слишком велика");
  const env = parse<{
    schemaVersion: string;
    payload: string;
    rootSignature: string;
  }>(policyText);
  assert(env.schemaVersion === "1.0", "Неподдерживаемая версия policy");
  const raw = base64Decode(env.payload);
  assert(raw.length <= 96 * 1024, "Payload trust policy слишком велик");
  await verify(
    root,
    Uint8Array.from([...bytes("Launcher-Trust-Policy-v1\n"), ...raw]),
    env.rootSignature,
  );
  const p = parse<Policy0355>(dec.decode(raw));
  const now = Date.now();
  assert(
    p.schemaVersion === "1.0" &&
      p.domain === "launcher.trust.v1" &&
      Number.isSafeInteger(p.epoch) &&
      p.epoch > 0 &&
      Array.isArray(p.keys) &&
      p.keys.length > 0 &&
      p.keys.length <= 128,
    "Неверная root-signed policy",
  );
  const issue = Date.parse(p.issuedAt),
    expiry = Date.parse(p.expiresAt);
  assert(
    [p.issuedAt, p.expiresAt].every((x) =>
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(x),
    ) &&
      Number.isFinite(issue) &&
      Number.isFinite(expiry) &&
      issue <= now + 300000 &&
      expiry > now &&
      expiry > issue &&
      expiry - issue <= 90 * 86400000,
    "Trust policy неактуальна",
  );
  return p;
}
export async function verifyBootstrap0355(
  signed: string,
  root: string,
  policyText = "",
): Promise<{
  envelope: Envelope0355;
  payload: Bootstrap0355;
  policy?: Policy0355;
}> {
  assert(
    bytes(signed).length <= 1024 * 1024,
    "Bootstrap превышает лимит 1 MiB",
  );
  hex(root, 32);
  const env = parse<Envelope0355>(signed);
  assert(
    env && ["1.0", "2.0"].includes(env.schemaVersion),
    "Неподдерживаемый signed bootstrap",
  );
  const raw = base64Decode(env.payload);
  assert(raw.length <= 1024 * 1024, "Payload bootstrap слишком велик");
  let key = root,
    message = raw,
    policy: Policy0355 | undefined;
  if (env.schemaVersion === "2.0") {
    assert(
      !!policyText,
      "Для delegated bootstrap нужна подписанная trust-policy.signed.json",
    );
    policy = await policy0355(policyText, root);
    assert(
      Number.isSafeInteger(env.trustEpoch) && env.trustEpoch === policy.epoch,
      "Неверный trustEpoch",
    );
    const active = policy.keys.find(
      (k) =>
        k.id === env.keyId && k.role === "bootstrap" && k.status === "active",
    );
    assert(
      active && Date.parse(active.notBefore) <= Date.now(),
      "Подписывающий bootstrap ключ недействителен",
    );
    const signedAt = Date.parse(env.signedAt || "");
    assert(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(env.signedAt || "") &&
        Number.isFinite(signedAt) &&
        signedAt <= Date.now() + 300000 &&
        signedAt >= Date.parse(active.notBefore),
      "Недопустимое время подписи",
    );
    key = active.publicKey;
    message = Uint8Array.from([
      ...bytes(
        `Launcher-Bootstrap-v2\n${env.keyId}\n${env.trustEpoch}\n${env.signedAt}\n`,
      ),
      ...raw,
    ]);
  } else
    assert(
      !policyText,
      "Нельзя выпустить legacy bootstrap при включённой delegated policy",
    );
  await verify(key, message, env.signature);
  const payload = parse<Bootstrap0355>(dec.decode(raw));
  assert(
    payload.schemaVersion === "1.0" &&
      typeof payload.projectId === "string" &&
      typeof payload.profileId === "string" &&
      typeof payload.profilePublicKey === "string",
    "Недействительная структура bootstrap",
  );
  if (env.schemaVersion === "2.0")
    assert(
      payload.profilePublicKey.toLowerCase() === root.toLowerCase(),
      "Delegated bootstrap должен закреплять root profilePublicKey",
    );
  if (payload.branding) validateBrand0355(payload.branding);
  return { envelope: env, payload, policy };
}
export async function signBranding0355(
  signed: string,
  root: string,
  seedHex: string,
  branding: Branding0355,
  policyText = "",
): Promise<string> {
  const input = await verifyBootstrap0355(signed, root, policyText);
  const next = { ...input.payload, branding: validateBrand0355(branding) };
  const raw = bytes(JSON.stringify(next));
  assert(raw.length <= 1024 * 1024, "Новый payload превышает лимит bootstrap");
  // 32-byte seed is imported non-extractably. No persistence and no Backend calls.
  const prefix = hex("302e020100300506032b657004220420", 16);
  const pkcs8 = Uint8Array.from([...prefix, ...hex(seedHex.trim(), 32)]);
  const signer = await crypto.subtle.importKey(
    "pkcs8",
    buffer(pkcs8),
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  pkcs8.fill(0);
  let message = raw;
  const output: Envelope0355 = {
    schemaVersion: input.envelope.schemaVersion,
    payload: base64Encode(raw),
    signature: "",
  };
  let expected = root;
  if (input.envelope.schemaVersion === "2.0") {
    const key = input.policy!.keys.find(
      (k) =>
        k.id === input.envelope.keyId &&
        k.role === "bootstrap" &&
        k.status === "active",
    );
    assert(key, "Активный delegated signer отсутствует");
    expected = key.publicKey;
    output.keyId = key.id;
    output.trustEpoch = input.policy!.epoch;
    output.signedAt = new Date().toISOString().slice(0, 19) + "Z";
    message = Uint8Array.from([
      ...bytes(
        `Launcher-Bootstrap-v2\n${output.keyId}\n${output.trustEpoch}\n${output.signedAt}\n`,
      ),
      ...raw,
    ]);
  }
  output.signature = hexString(
    new Uint8Array(
      await crypto.subtle.sign("Ed25519", signer, buffer(message)),
    ),
  );
  await verify(expected, message, output.signature); // seed must match the installed trust root / delegated key
  const json = JSON.stringify(output, null, 2) + "\n";
  await verifyBootstrap0355(json, root, policyText); // final round trip, no unchecked download
  return json;
}
export async function readPng0355(file: File): Promise<string> {
  assert(
    file.size >= 24 && file.size <= 131072,
    "PNG должен быть не больше 128 KiB",
  );
  const raw = new Uint8Array(await file.arrayBuffer());
  const encoded = base64Encode(raw);
  image(encoded);
  return encoded;
}
