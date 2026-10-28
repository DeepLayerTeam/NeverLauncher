import React, { useCallback, useEffect, useState } from 'react';
import { ReleaseApi, type ValidationAuditReport03412 } from '../api/release';

type Props = {api:ReleaseApi; packageId:string};
const readableTime = (value?:string) => value ? new Date(value).toLocaleString() : '—';

/** This screen does not send an administrative certification decision. Its
 * eligibility comes only from Backend's live signed-evidence evaluator. */
export function ValidationHistory03412({api,packageId}:Props) {
  const [report,setReport] = useState<ValidationAuditReport03412|null>(null);
  const [events,setEvents] = useState<ValidationAuditReport03412['attempts']>([]);
  const [next,setNext] = useState(0);
  const [selected,setSelected] = useState<ValidationAuditReport03412|null>(null);
  const [busy,setBusy] = useState(false);
  const [error,setError] = useState('');
  const load=useCallback(async (cursor=0) => {
    if(!packageId) return;
    setBusy(true);setError('');
    try {
      const value=await api.validationReport(packageId,cursor);
      setReport(value);
      setEvents(old=>cursor===0 ? value.attempts : [...old,...value.attempts]);
      setNext(value.nextBefore);
    } catch (e) {setError(e instanceof Error?e.message:String(e));}
    finally {setBusy(false)}
  },[api,packageId]);
  useEffect(()=>{setReport(null);setSelected(null);setEvents([]);setNext(0);void load(0);},[load]);
  async function drill(runId:string) {
    setBusy(true);setError('');
    try {setSelected(await api.validationRun(packageId,runId));}
    catch(e){setError(e instanceof Error?e.message:String(e));}
    finally{setBusy(false)}
  }
  if (!packageId) return null;
  return <section className="subcard" aria-label="Validation V12 audit trail">
    <h3>Runtime validation · журнал V12</h3>
    <div className="buttonRow"><button disabled={busy} onClick={()=>void load(0)}>Обновить аудит</button></div>
    {error && <p role="alert" className="error">{error}</p>}
    {report && <>
      <p><strong>Policy:</strong> {report.policy.requiredLevel}; stable: {report.coverage.stablePublishEligible?'подтверждено':'заблокировано'}; targets: {report.coverage.verified}/{report.coverage.required}.</p>
      <p className="muted">Доказательства проверяются Backend при каждом запросе. Административная отметка certified не предусмотрена.</p>
      {Object.keys(report.coverage.targetBlockers).length>0 && <details open><summary>Причины блокировки ({Object.keys(report.coverage.targetBlockers).length})</summary><ul>{Object.entries(report.coverage.targetBlockers).map(([target,reason])=><li key={target}><code>{target}</code>: {reason}</li>)}</ul></details>}
      <details open><summary>Попытки и решения ({events.length}{report.hasMore?' +':''})</summary>
        {events.length===0?<p>Попыток не обнаружено.</p>:<table><thead><tr><th>Время</th><th>Событие</th><th>Результат</th><th>Причина</th><th>Run / SHA-256</th></tr></thead><tbody>
        {events.map(ev=><tr key={ev.id}><td>{readableTime(ev.createdAt)}</td><td>{ev.kind}</td><td>{ev.outcome}</td><td>{ev.reasonCode}</td><td>{ev.runId?<button disabled={busy} onClick={()=>void drill(ev.runId)}>{ev.runId}</button>:'—'}<p><code title={ev.payloadSha256}>{ev.payloadSha256.slice(0,20)}…</code></p></td></tr>)}
        </tbody></table>}
        {next>0 && <button disabled={busy} onClick={()=>void load(next)}>Загрузить предыдущие события</button>}
      </details>
      {selected && <section className="subcard" aria-label="Selected historic run">
        <div className="buttonRow"><strong>Исторический запуск {selected.runs[0]?.runId}</strong><button onClick={()=>setSelected(null)}>Закрыть</button></div>
        {selected.runs.map(run=><ul key={run.runId}>{Object.entries(run.stages).map(([name,stage])=><li key={name}>{name}: {stage.status} · {stage.detail||'—'} {stage.evidenceSha256&&<code>{stage.evidenceSha256}</code>}</li>)}</ul>)}
        {selected.evidence.map(ev=><p key={ev.runId}>Evidence: {ev.status} · SHA-256 <code>{ev.evidenceSha256}</code> · expires {readableTime(ev.expiresAt)}</p>)}
      </section>}
      <details><summary>Запуски и стадии ({report.runs.length})</summary>
        {report.runs.map(run=><article key={run.runId} className="subcard"><strong>Run <code>{run.runId}</code></strong> · {readableTime(run.receivedAt)} · observation (не сертификат)
          <ul>{Object.entries(run.stages).map(([name,stage])=><li key={name}><strong>{name}</strong>: {stage.status} {stage.detail&&<span>· {stage.detail}</span>} {stage.evidenceSha256&&<code title={stage.evidenceSha256}> · SHA {stage.evidenceSha256.slice(0,16)}…</code>}</li>)}</ul>
        </article>)}
      </details>
      <details open><summary>ValidationEvidence ({report.evidence.length})</summary>
        {report.evidence.map(ev=><p key={ev.runId}><code>{ev.targetId||ev.runId}</code> · {ev.status} · expiry {readableTime(ev.expiresAt)} · SHA-256 <code title={ev.evidenceSha256}>{ev.evidenceSha256.slice(0,20)}…</code></p>)}
      </details>
    </>}
  </section>;
}
