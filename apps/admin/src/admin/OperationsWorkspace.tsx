import React, { useEffect, useRef, useState } from 'react';
import { requestJSON } from '../api/client';
import { TextInput } from '../components/primitives';
import { ReleaseApi } from '../api/release';
import { durableOwnerKey } from './owner-recovery-0388';

type Kind = 'channel-rollback' | 'package-publish';
type Job = { id: string; kind: Kind; status: string; lastError?: string; result?: Record<string, unknown>; attemptCount: number; maxAttempts: number; createdAt: string; completedAt?: string };
type Attempt = { attempt: number; status: string; startedAt: string; finishedAt?: string; error?: string };
type Validation = { valid: boolean; permission: string; effect: Record<string, string> };
type OperationIntent = { kind: Kind; projectId: string; resourceId?: string; profileId: string; channel: string; toVersion: string; idempotencyKey: string };
type Recoverable = { intent: OperationIntent; jobId?: string };
// No credentials are stored; use the verified account identity, not a rotating session.
const recoveryKey = (base:string, project:string, userId:string) => durableOwnerKey(base,userId,project,'operations');
function readRecovery(base:string,project:string,userId:string): Recoverable|null {
  if(!userId || !project) return null;
  try {
    const value:Recoverable|null=JSON.parse(localStorage.getItem(recoveryKey(base,project,userId))||'null');
    if(value?.intent?.projectId===project && value.intent.idempotencyKey?.length>=8 &&
      ['package-publish','channel-rollback'].includes(value.intent.kind) &&
      (!value.jobId || typeof value.jobId==='string'))return value;
  }catch{/* Untrusted browser state is not executable */}
  return null;
}

export function OperationsWorkspace({ backendUrl, token, projectId, canPublish, userId }: { backendUrl: string; token: string; projectId: string; canPublish: boolean; userId: string }) {
  const [kind, setKind] = useState<Kind>('channel-rollback');
  const [profileId, setProfileId] = useState('vanilla');
  const [channel, setChannel] = useState('stable');
  const [toVersion, setToVersion] = useState('');
  const [packageId, setPackageId] = useState('');
  const [idempotencyKey, setIdempotencyKey] = useState(() => crypto.randomUUID());
  const [validation, setValidation] = useState<Validation | null>(null);
  const [jobId, setJobId] = useState('');
  const [job, setJob] = useState<Job | null>(null);
  const [attempts, setAttempts] = useState<Attempt[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const inFlight = useRef(false);
  const [recoverable, setRecoverable] = useState<Recoverable | null>(() => readRecovery(backendUrl, projectId, userId));
  const persist = (value: Recoverable | null) => {
    setRecoverable(value);
    if (value) localStorage.setItem(recoveryKey(backendUrl, projectId, userId), JSON.stringify(value));
    else localStorage.removeItem(recoveryKey(backendUrl, projectId, userId));
  };
  const resetPreview = () => { setValidation(null); setIdempotencyKey(crypto.randomUUID()); };

  const request = { kind, projectId, resourceId: kind === 'package-publish' ? packageId : undefined, profileId, channel, toVersion, idempotencyKey };
  async function refresh(id = jobId) {
    if (!id) return;
    const current = await requestJSON<Job>(backendUrl, `/api/v1/operations/${encodeURIComponent(id)}`, token);
    setJob(current);
    const history = await requestJSON<{ attempts: Attempt[] }>(backendUrl, `/api/v1/operations/${encodeURIComponent(id)}/attempts`, token);
    setAttempts(history.attempts || []);
  }
  useEffect(() => {
    setJob(null); setJobId(''); setAttempts([]); setValidation(null);
    const saved = readRecovery(backendUrl, projectId, userId);
    setRecoverable(saved);
    setIdempotencyKey(saved?.intent.idempotencyKey || crypto.randomUUID());
    if (saved?.jobId) setJobId(saved.jobId);
  }, [projectId, backendUrl, token, userId]);
  useEffect(() => {
    if (!jobId || ['succeeded', 'failed', 'dead', 'revoked'].includes(job?.status ?? '')) return;
    let active = true;
    const id = window.setInterval(() => { if (active) refresh(jobId).catch(err => setError(String(err.message))); }, 2000);
    return () => { active = false; window.clearInterval(id); };
  }, [jobId, job?.status, token, backendUrl]);

  async function perform(action: 'validate' | 'execute', recovery = false) {
    if (inFlight.current || busy) return;
    if (recoverable && !recovery) { setError('Есть незавершённый запрос. Сначала восстановите его по исходному ключу или проверьте результат в аудите.'); return; }
    if (recovery && !recoverable) return;
    if (action === 'execute' && !recovery && !validation?.valid) { setError('Сначала выполните validate.'); return; }
    if (action === 'execute' && !recovery && !window.confirm(`Подтвердить ${kind} в проекте ${projectId}?\n${Object.entries(validation?.effect ?? {}).map(([k,v]) => `${k}: ${v}`).join('\n')}`)) return;
    inFlight.current = true; setBusy(true); setError('');
    const intent = recovery ? recoverable!.intent : request;
    try {
    if (action === 'execute' && !recovery) {
      if (readRecovery(backendUrl,projectId,userId)) {setError('Другая вкладка сохранила незавершённую операцию. Обновите страницу, чтобы восстановить исходный job.');inFlight.current=false;setBusy(false);return;}
      persist({ intent }); // Before transport, including an ACK loss.
    }
      if(recovery) {
        const existing=await new ReleaseApi(backendUrl,token).recoverOperation(intent.projectId,intent.kind,intent.idempotencyKey);
        if(existing.projectId!==intent.projectId || existing.kind!==intent.kind ||
          existing.resourceId!==(intent.kind==='package-publish'?intent.resourceId:intent.channel) ||
          (recoverable?.jobId && recoverable.jobId!==existing.id))throw Error('Журнал вернул чужую операцию');
        persist({intent,jobId:existing.id});setJobId(existing.id);await refresh(existing.id);
        return;
      }
      const data = await requestJSON<Validation | Job>(backendUrl, `/api/v1/operations/${action}`, token, { method: 'POST', body: JSON.stringify(intent) });
      if (action === 'validate') setValidation(data as Validation);
      else {
        const created = data as Job;
        persist({intent, jobId: created.id});
        setJobId(created.id); setJob(created); setAttempts([]);
        await refresh(created.id);
      }
    } catch (err) { setError(err instanceof Error ? err.message : String(err)); }
    finally { inFlight.current = false; setBusy(false); }
  }
  async function retryOriginalIntent(){
    if(!recoverable || recoverable.jobId || !canPublish || busy)return;
    if(!window.confirm('Серверный журнал пока не содержит этот job. Повторить строго сохранённый запрос с исходным idempotency key? Потребуется действующая MFA.'))return;
    inFlight.current=true;setBusy(true);setError('');
    try{
      const api=new ReleaseApi(backendUrl,token);
      const {intent}=recoverable;
      let existing;
      try{existing=await api.recoverOperation(intent.projectId,intent.kind,intent.idempotencyKey)}
      catch(e){if(!(typeof e==='object' && e!==null && 'status' in e && e.status===404))throw e;}
      const next=existing??await api.executeOperation(intent);
      if(!next.id || next.projectId!==intent.projectId || next.kind!==intent.kind ||
          next.resourceId!==(intent.kind==='package-publish'?intent.resourceId:intent.channel))throw Error('Неверный ответ журнала операций');
      persist({intent,jobId:next.id});setJobId(next.id);await refresh(next.id);
    }catch(e){setError(e instanceof Error?e.message:String(e))}
    finally{inFlight.current=false;setBusy(false)}
  }
  // Read-only check after login or refresh. A missing record does not create a job.
  useEffect(()=>{
    if(!recoverable || recoverable.jobId || !token)return;
    let live=true;
    const {intent}=recoverable;
    void new ReleaseApi(backendUrl,token).recoverOperation(intent.projectId,intent.kind,intent.idempotencyKey).then(existing=>{
      if(!live)return;
      if(existing.projectId!==intent.projectId || existing.kind!==intent.kind ||
        existing.resourceId!==(intent.kind==='package-publish'?intent.resourceId:intent.channel))throw Error('Журнал вернул чужое задание');
      persist({intent,jobId:existing.id});setJobId(existing.id);
    }).catch(e=>{if(live && e?.status!==404)setError(String(e?.message||e))});
    return ()=>{live=false};
  },[recoverable?.intent.idempotencyKey,recoverable?.jobId,token,backendUrl,userId,projectId]);
  async function modifyJob(action: 'cancel' | 'retry') {
    if (!job || !window.confirm(`${action} для операции ${job.id}?`)) return;
    setBusy(true); setError('');
    try {
      const next = await requestJSON<Job>(backendUrl, `/api/v1/operations/${encodeURIComponent(job.id)}/${action}`, token, { method: 'POST' });
      setJob(next); await refresh(job.id);
    } catch (err) { setError(err instanceof Error ? err.message : String(err)); }
    finally { setBusy(false); }
  }

  return <section className="card wide">
    <h2>Unified Operations · {__NEVERLAUNCHER_VERSION__}</h2>
    <p className="muted">Идемпотентные серверные операции. Результат и история сохраняются на Backend при закрытии браузера.</p>
    <div className="formGrid"><article className="subcard">
      <label className="field"><span>Операция</span><select value={kind} onChange={e => { setKind(e.target.value as Kind); resetPreview(); }}><option value="channel-rollback">Откат канала</option><option value="package-publish">Публикация пакета</option></select></label>
      <TextInput label="Проект" value={projectId} readOnly onChange={() => {}} />
      {kind === 'channel-rollback' ? <>
        <TextInput label="Профиль" value={profileId} onChange={v => { setProfileId(v); resetPreview(); }} />
        <TextInput label="Канал" value={channel} onChange={v => { setChannel(v); resetPreview(); }} />
        <TextInput label="Версия для отката" value={toVersion} onChange={v => { setToVersion(v); resetPreview(); }} />
      </> : <TextInput label="ID пакета" value={packageId} onChange={v => { setPackageId(v); resetPreview(); }} />}
      <TextInput label="Idempotency key (повтор использует тот же job)" value={idempotencyKey} onChange={v => { setIdempotencyKey(v); setValidation(null); }} />
      {recoverable && <div className="subcard" role="alert"><p><strong>Есть сохранённая операция с неизвестным или уже принятым результатом.</strong> Повтор допустим только с исходным ключом. После перезагрузки не создавайте новую операцию без проверки job и аудита.</p><p>Ключ: <code>{recoverable.intent.idempotencyKey}</code>{recoverable.jobId ? <> · Job: <code>{recoverable.jobId}</code></> : null}</p><div className="buttonRow"><button disabled={busy} onClick={() => void perform('execute', true)}>Найти исходный job (без повторного исполнения)</button><button disabled={busy||!job||!['succeeded','failed','dead','revoked','cancelled'].includes(job.status)} onClick={() => { if (window.confirm('Вы проверили результат в job и аудите? Новый ключ может создать повторный rollback. Сбросить восстановление?')) { persist(null); setValidation(null); setIdempotencyKey(crypto.randomUUID()); } }}>После проверки начать новую операцию</button>{!recoverable.jobId && <button disabled={busy||!canPublish} onClick={() => void retryOriginalIntent()}>Повторить исходный запрос (после проверки)</button>}</div></div>}
      <div className="buttonRow"><button disabled={busy || !!recoverable || !canPublish || !projectId} onClick={() => void perform('validate')}>Проверить эффект</button><button disabled={busy || !!recoverable || !canPublish || !validation?.valid} onClick={() => void perform('execute')}>Выполнить</button></div>
      {validation && <div className="subcard"><p><strong>Проверка пройдена</strong> · {validation.permission}</p>{Object.entries(validation.effect).map(([key,value]) => <p key={key}><strong>{key}:</strong> {value}</p>)}</div>}
    </article>
    <article className="subcard">
      <h3>Задание и журнал исполнения</h3>
      <TextInput label="ID задания (для восстановления после перезагрузки)" value={jobId} onChange={v => { setJobId(v); setJob(null); setAttempts([]); }} />
      <div className="buttonRow"><button disabled={!jobId || busy} onClick={() => refresh().catch(err => setError(String(err.message)))}>Обновить</button>
        <button disabled={!canPublish || busy || job?.status !== 'pending'} onClick={() => modifyJob('cancel')}>Отменить ожидающее</button>
        <button disabled={!canPublish || busy || !['failed','revoked','dead'].includes(job?.status ?? '')} onClick={() => modifyJob('retry')}>Повторить</button>
      </div>
      {job && <><p><strong>Correlation ID:</strong> <code>{job.id}</code></p><p><strong>Состояние:</strong> {job.status} · попыток: {job.attemptCount}/{job.maxAttempts}</p>
        {job.lastError && <p className="error">{job.lastError}</p>}
        {job.result && <div><h4>Результат</h4>{Object.entries(job.result).filter(([,v]) => typeof v !== 'object').map(([key,value]) => <p key={key}>{key}: {String(value)}</p>)}</div>}
        <table className="table"><thead><tr><th>Попытка</th><th>Статус</th><th>Начало</th><th>Ошибка</th></tr></thead><tbody>{attempts.length ? attempts.map(a => <tr key={a.attempt}><td>{a.attempt}</td><td>{a.status}</td><td>{a.startedAt}</td><td>{a.error || '—'}</td></tr>) : <tr><td colSpan={4}>Попыток пока нет</td></tr>}</tbody></table>
      </>}
    </article></div>
    {error && <div role="alert" className="error">{error}</div>}
  </section>;
}
