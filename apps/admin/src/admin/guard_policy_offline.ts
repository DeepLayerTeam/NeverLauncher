// Operator workflow: only independently pinned Ed25519 public keys may verify
// Guard envelopes. The web Admin never receives private signing keys.
export type GuardContent05011 = {
  schemaVersion: 'launcher.guard-compatibility.v1';
  projectId: string; minecraft: string; loader: string;
  epoch: number; issuedAt: number; expiresAt: number;
  artifacts: { kind: string; path: string; sha256: string }[];
  transformations: { id: string; ownerSha256: string }[];
  revokedDigests: string[]; revokedTransformations: string[];
  loaderClassBytes?: { class: string; sha256: string }[];
  externalNativeModules?: { path: string; sha256: string }[];
};
export type SignedGuard05011 = {schemaVersion: string; payload: string; signature: string};
const DOMAIN = new TextEncoder().encode('NeverLauncher-Guard-Compatibility-v1\n');
function hexBytes(value: string): Uint8Array {
  if (!/^(?:[a-f0-9]{2})+$/.test(value)) throw Error('Неверный hex');
  return Uint8Array.from(value.match(/../g)!, s => parseInt(s, 16));
}
function decodeBase64(value: string): Uint8Array {
  if (value.length > 256 * 1024 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw Error('Некорректный payload Base64');
  return Uint8Array.from(atob(value), s => s.charCodeAt(0));
}
function parsePolicy(raw: Uint8Array): GuardContent05011 {
  if (!raw.length || raw.length > 192*1024) throw Error('Слишком большой payload');
  const decoded = JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(raw)) as GuardContent05011;
  if (decoded.schemaVersion !== 'launcher.guard-compatibility.v1' || !Number.isSafeInteger(decoded.epoch) || decoded.epoch < 1 ||
      !decoded.projectId || !decoded.minecraft || !decoded.loader || !Array.isArray(decoded.artifacts) ||
      !Array.isArray(decoded.transformations) || !Array.isArray(decoded.revokedDigests) || !Array.isArray(decoded.revokedTransformations) ||
      !Number.isSafeInteger(decoded.issuedAt) || !Number.isSafeInteger(decoded.expiresAt) || decoded.expiresAt <= decoded.issuedAt) {
    throw Error('Неподдерживаемая или повреждённая Guard policy');
  }
  return decoded;
}
export async function verifyGuardEnvelope05011(envelopeJSON: string, pinnedPublicKey: string, at: number = Math.floor(Date.now()/1000), allowExpired = false) {
  const publicBytes = hexBytes(pinnedPublicKey.trim());
  if (publicBytes.length !== 32) throw Error('Требуется внешний Ed25519 public key, 64 hex');
  if (envelopeJSON.length > 256*1024) throw Error('Guard envelope слишком большой');
  const env = JSON.parse(envelopeJSON) as SignedGuard05011;
  if (env.schemaVersion !== 'launcher.guard-compatibility.v1' || typeof env.payload !== 'string' || typeof env.signature !== 'string') throw Error('Неизвестный Guard envelope');
  const payloadBytes = decodeBase64(env.payload);
  const signature = hexBytes(env.signature);
  if (signature.length !== 64) throw Error('Некорректная подпись Ed25519');
  if (!globalThis.crypto?.subtle) throw Error('WebCrypto недоступен: требуется HTTPS/современный браузер');
  const key = await crypto.subtle.importKey('raw', publicBytes as BufferSource, {name:'Ed25519'}, false, ['verify']);
  const signed = new Uint8Array(DOMAIN.length + payloadBytes.length);
  signed.set(DOMAIN); signed.set(payloadBytes, DOMAIN.length);
  if (!await crypto.subtle.verify({name:'Ed25519'}, key, signature as BufferSource, signed as BufferSource)) throw Error('Подпись Ed25519 не подтверждена');
  const policy = parsePolicy(payloadBytes);
  if (policy.issuedAt > at+300 || (!allowExpired && policy.expiresAt <= at) || policy.expiresAt - policy.issuedAt > 90*86400) throw Error('Подписанная политика просрочена или выпущена в будущем');
  return policy;
}
export function guardCandidate05011(current: GuardContent05011, previous: GuardContent05011|null, digestList: string, transformList: string, now = Math.floor(Date.now()/1000)): GuardContent05011 {
  if (!Number.isSafeInteger(current.epoch+1)) throw Error('Исчерпана точность epoch');
  if (previous && (previous.epoch >= current.epoch || previous.projectId !== current.projectId || previous.minecraft !== current.minecraft || previous.loader.toLowerCase() !== current.loader.toLowerCase())) throw Error('Историческая политика не относится к данной сборке или не старше текущей');
  const digest = digestList.split(/[\s,]+/).filter(Boolean);
  if (digest.some(x => !/^[a-f0-9]{64}$/.test(x))) throw Error('Отзыв JAR/native требует SHA-256 lowercase hex');
  const transforms = transformList.split(/[\n,]+/).map(x=>x.trim()).filter(Boolean);
  if (transforms.some(x => x.length>256)) throw Error('Идентификатор трансформации слишком длинный');
  if (!previous && digest.length===0 && transforms.length===0) throw Error('Для новой эпохи требуется отзыв или историческая конфигурация');
  const target = previous ?? current;
  const revokedDigests = Array.from(new Set([...current.revokedDigests, ...target.revokedDigests, ...digest]));
  const revokedTransformations = Array.from(new Set([...current.revokedTransformations, ...target.revokedTransformations, ...transforms]));
  if (revokedDigests.length>4096 || revokedTransformations.length>4096) throw Error('Список отзыва слишком длинный');
  return {...target, epoch:current.epoch+1, issuedAt:now,expiresAt:now+7*86400,revokedDigests,revokedTransformations};
}
export function guardCandidateAllowed05011(current:GuardContent05011,candidate:GuardContent05011) {
  if (candidate.epoch<=current.epoch || candidate.projectId!==current.projectId || candidate.minecraft!==current.minecraft || candidate.loader.toLowerCase()!==current.loader.toLowerCase()) throw Error('Кандидат не повышает epoch или меняет область доверия');
  if (current.revokedDigests.some(x=>!candidate.revokedDigests.includes(x)) || current.revokedTransformations.some(x=>!candidate.revokedTransformations.includes(x))) throw Error('Нельзя снять ранее подписанный отзыв');
}
