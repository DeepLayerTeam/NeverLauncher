/** Only a reviewed, allowlisted native report can enter the support submission path. */
export type PlayerDiagnosticEvent03510 = { code: string; count: number };
export type PlayerDiagnosticReport03510 = { schemaVersion:'1.1'; launcherVersion:string; generatedAtUnix:number; os:string; arch:string; stage:string; events:PlayerDiagnosticEvent03510[] };
export type PlayerDiagnosticPreview03510 = { reviewToken:string; report:PlayerDiagnosticReport03510 };
const codes=new Set(['signature','offline-cache','download','authentication','integrity','runtime','recovery','permission','other-error','other']);
const stages=new Set(['idle','ready','installing','checking','running','failed','downloading','staged','verifying','launching','other']);
export function ensureReviewedDiagnostic03510(preview:PlayerDiagnosticPreview03510|null,consent:boolean,accessToken:string|undefined):PlayerDiagnosticReport03510 {
  if (!consent) throw new Error('Сначала подтвердите отправку обезличенного отчёта.');
  if (!accessToken) throw new Error('Для отправки отчёта войдите в аккаунт.');
  if (!preview?.reviewToken || !/^[a-f0-9]{48}$/.test(preview.reviewToken)) throw new Error('Сначала откройте предпросмотр диагностики.');
  const r=preview.report;
  if(r.schemaVersion!=='1.1'||!stages.has(r.stage)||!Array.isArray(r.events)||r.events.length>10) throw new Error('Отчёт не соответствует безопасному формату.');
  if(r.events.some(e=>!codes.has(e.code)||!Number.isInteger(e.count)||e.count<1||e.count>80)) throw new Error('В отчёте обнаружены неподдерживаемые данные.');
  return r;
}
