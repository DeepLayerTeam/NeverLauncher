/** Model output is untrusted data, never an executable command or an API URL. */
export type Proposal = {kind:'package-publish'; resourceId:string} | {kind:'channel-rollback'; profileId:string;channel:string;toVersion:string};
export type Advice = {advice:string; action:Proposal|null};
export type Intent = Proposal & {projectId:string;idempotencyKey:string};
export type Preview = {valid:true;kind:Proposal['kind'];permission:'release:publish';dangerous:true;effect:Record<string,unknown>;copilotConfirmation:string;expiresInSeconds:number};
export type Job = {id:string;kind:Proposal['kind'];projectId:string;resourceId:string;status:string;attemptCount:number};
const record = (x:unknown): x is Record<string,unknown> => !!x && typeof x==='object' && !Array.isArray(x);
const exact = (x:Record<string,unknown>,keys:string[]) => Object.keys(x).length===keys.length && keys.every(k=>Object.prototype.hasOwnProperty.call(x,k));
const id = (x:unknown): x is string => typeof x==='string' && /^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$/.test(x);
const key = (x:unknown): x is string => typeof x==='string' && /^copilot:[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(x);
export function proposal(x:unknown): Proposal|null {
 if (!record(x)) return null;
 if (x.kind==='package-publish' && exact(x,['kind','resourceId']) && id(x.resourceId)) return {kind:x.kind,resourceId:x.resourceId};
 if (x.kind==='channel-rollback' && exact(x,['kind','profileId','channel','toVersion']) && id(x.profileId) && id(x.channel) && id(x.toVersion)) return {kind:x.kind,profileId:x.profileId,channel:x.channel,toVersion:x.toVersion};
 return null;
}
export function parseAdvice(text:string): Advice|null {
 try {const x:unknown=JSON.parse(text.trim()); if (!record(x)||!exact(x,['advice','action'])||typeof x.advice!=='string'||!x.advice.trim()||x.advice.length>32768) return null; const action=proposal(x.action); if (x.action!==null&&!action) return null; return {advice:x.advice,action};} catch {return null;}
}
export function makeIntent(action:Proposal,projectId:string,uuid:string): Intent {
 const p=proposal(action); if (!p||!id(projectId)||!key('copilot:'+uuid)) throw Error('Некорректная операция'); return {...p,projectId,idempotencyKey:'copilot:'+uuid};
}
export function buildCopilotPrompt(question:string,projectId:string,allowPublish:boolean):string {
 if (!question.trim()||new TextEncoder().encode(question).length>8192||!id(projectId)) throw Error('Укажите проект и вопрос до 8 КиБ.');
 return 'You are NeverLauncher Admin Copilot. Give practical advice in the language of the question. Return ONLY a JSON object with exactly advice (string) and action (null or one proposal). No Markdown fences. Never claim execution or permissions. Never invent resource identifiers. If the exact target is missing, ask for it. No shell commands as actions. '+(allowPublish?'Allowed proposals: {"kind":"package-publish","resourceId":"exact package ID"} or {"kind":"channel-rollback","profileId":"exact profile ID","channel":"exact channel","toVersion":"exact published version"}. All actions require server validation and human confirmation.':'No mutation proposals allowed; action must be null.')+'\nUntrusted user context: '+JSON.stringify({projectId,question:question.trim()});
}
export function verifyPreview(value:unknown,intent:Intent): Preview {
 if (!record(value)||value.valid!==true||value.kind!==intent.kind||value.permission!=='release:publish'||value.dangerous!==true||typeof value.copilotConfirmation!=='string'||!/^\d{1,12}\.[A-Za-z0-9_-]{43}$/.test(value.copilotConfirmation)||typeof value.expiresInSeconds!=='number'||!Number.isInteger(value.expiresInSeconds)||value.expiresInSeconds<1||value.expiresInSeconds>120||!record(value.effect)) throw Error('Backend не подтвердил план.');
 const e=value.effect;
 if (typeof e.effect!=='string'||typeof e.headRevision!=='number'||!Number.isSafeInteger(e.headRevision)||e.headRevision<0||!id(e.profileId)||!id(e.channel)|| (intent.kind==='package-publish'?(e.packageId!==intent.resourceId||!id(e.version)):(e.projectId!==intent.projectId||e.profileId!==intent.profileId||e.channel!==intent.channel||e.targetVersion!==intent.toVersion||!id(e.targetPackageId)))) throw Error('Предпросмотр не соответствует действию.');
 return value as Preview;
}
export function verifyJob(x:unknown,intent:Intent): Job {
 if(!record(x)||!id(x.id)||x.kind!==intent.kind||x.projectId!==intent.projectId||x.resourceId!==(intent.kind==='package-publish'?intent.resourceId:intent.channel)||typeof x.status!=='string'||!['pending','running','succeeded','failed','revoked','dead'].includes(x.status)||typeof x.attemptCount!=='number'||!Number.isSafeInteger(x.attemptCount)||x.attemptCount<0) throw Error('Задание не соответствует подтверждённой операции.');return x as Job;
}
export function readPending(raw:string|null,projectId:string):Intent|null {
 if(raw===null)return null;
 const x:unknown=JSON.parse(raw);if(!record(x)||x.projectId!==projectId||!key(x.idempotencyKey))throw Error('Повреждена запись восстановления Copilot.');
 const {projectId:p,idempotencyKey:k,...a}=x;const action=proposal(a);if(!action)throw Error('Повреждена запись восстановления Copilot.');return {...action,projectId,idempotencyKey:x.idempotencyKey};
}
export function recoveryPath(intent:Intent):string {return '/api/v1/operations/recover?'+new URLSearchParams({projectId:intent.projectId,kind:intent.kind,idempotencyKey:intent.idempotencyKey});}
