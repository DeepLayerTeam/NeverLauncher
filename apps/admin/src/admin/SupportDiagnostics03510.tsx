import React, { useEffect, useState } from 'react';
import { requestJSON } from '../api/client';

type PlayerEvent = { code: string; count: number };
type SupportReport = { id: string; receivedAt: string; report: { launcherVersion: string; os: string; arch: string; stage: string; events: PlayerEvent[] } };

function saveJSON(name: string, data: unknown) {
  const blob = new Blob([JSON.stringify(data, null, 2)], {type:'application/json'});
  const url = URL.createObjectURL(blob);
  try {
    const anchor = document.createElement('a');anchor.href=url;anchor.download=name;anchor.click();
  } finally {setTimeout(()=>URL.revokeObjectURL(url),1000);}
}
export function SupportDiagnostics03510({backendUrl, token}: {backendUrl:string;token:string}) {
  const [operator,setOperator] = useState<Record<string,unknown>|null>(null);
  const [reports,setReports] = useState<SupportReport[]>([]);
  const [selected,setSelected] = useState('');
  const [loading,setLoading] = useState(false);
  const [error,setError] = useState('');
  async function refresh() {
    setLoading(true);setError('');
    try {
      const [bundle,inbox] = await Promise.all([
        requestJSON<Record<string,unknown>>(backendUrl,'/api/v1/operations/diagnostics-bundle',token),
        requestJSON<{items:SupportReport[]}>(backendUrl,'/api/v1/operations/support-reports',token),
      ]);
      setOperator(bundle);setReports(Array.isArray(inbox.items)?inbox.items:[]);
    } catch (e) {setError(String(e));} finally {setLoading(false);}
  }
  useEffect(()=>{void refresh();},[backendUrl,token]);
  const detail=reports.find(v=>v.id===selected);
  return <section className="card wide" aria-label="Операторская диагностика">
    <h2>Operator Diagnostics & Support</h2>
    <p>Отчёты игроков содержат только категории событий, без файлов, токенов, URL и имён. Доступ ограничен разрешением diagnostics:read.</p>
    <div className="buttonRow"><button onClick={()=>void refresh()} disabled={loading}>Обновить диагностику</button>
      <button disabled={!operator} onClick={()=>saveJSON('neverlauncher-operator-diagnostics.json',operator)}>Экспортировать проверенный операторский пакет</button>
    </div>
    {error && <p role="alert" className="error">{error}</p>}
    {operator && <><h3>Состояние Backend</h3><pre>{JSON.stringify({checks:operator.checks,counts:operator.counts,config:operator.config},null,2)}</pre></>}
    <h3>Отчёты поддержки ({reports.length}{reports.length===100?'+':''})</h3>
    <ul>{reports.map(v=><li key={v.id}><button aria-pressed={v.id===selected} onClick={()=>setSelected(v.id)}>{v.receivedAt} · {v.report.os} · {v.report.stage} · {v.id.slice(0,8)}</button></li>)}</ul>
    {detail&&<><h4>Диагностика {detail.id}</h4><pre>{JSON.stringify(detail.report,null,2)}</pre><button onClick={()=>saveJSON(`neverlauncher-support-${detail.id}.json`,detail)}>Экспортировать обезличенный отчёт</button></>}
    {!loading&&reports.length===0&&<p>Отчёты пока не отправлены. Игрок должен сначала посмотреть состав и явно согласиться на отправку в Desktop.</p>}
  </section>;
}
