/** Package validate is a semantic decision, not an HTTP transport result.
 * Backend intentionally returns 200 with status=invalid and detailed blockers. */
export type PackageValidation0390 = {
  status?: string;
  checks?: Array<{id:string;status:string;reasonCode?:string;message?:string}>;
  blockers?: Array<{reasonCode:string;resource:string;message:string;action:string}>;
};
export function requireValidatedPackage0390(result:PackageValidation0390): PackageValidation0390 {
  if (result?.status === 'valid' && Array.isArray(result.checks) && result.checks.length > 0 &&
      result.checks.every(check => check.status === 'ok')) return result;
  const reasons = (result?.blockers?.length ? result.blockers.map(b=>`${b.reasonCode} (${b.resource}): ${b.message}. ${b.action}`) :
    result?.checks?.filter(c=>c.status!=='ok').map(c=>`${c.reasonCode||c.id}: ${c.message||'не пройдено'}`)) || [];
  throw new Error(`Backend отклонил Validate: ${reasons.join('; ')||'нет подтверждения корректности пакета'}`);
}
