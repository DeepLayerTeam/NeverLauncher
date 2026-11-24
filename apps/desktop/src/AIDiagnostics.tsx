import React, {useEffect, useRef, useState} from 'react';
import {diagnosticQuestion, findings, IMPORT_SOURCES, localReport, MAX_LOG_FILES, RULES, scanFile, type ImportSource, type LocalSnapshot, type Report, type Scan} from './ai_diagnostics';
import type {Locale0357} from './desktop_accessibility';

type Props = {snapshot: LocalSnapshot; locale: Locale0357; disabled?: boolean; onDraft?: (question: string) => void; hasDraft?: boolean};
const names: Record<string, [string,string]> = {
  launcher:['Лаунчер','Launcher'], java:['Проверка Java','Java check'], download:['Загрузки','Downloads'], runtime:['Запуск игры','Game launch'], 'file-check':['Проверка файлов','File check'],
  'minecraft-log':['Лог Minecraft','Minecraft log'], 'crash-report':['Crash-report / hs_err','Crash report / hs_err'], 'mod-log':['Лог модификаций','Mod log'], 'java-log':['Лог Java','Java log'], 'download-log':['Лог загрузки','Download log'],
};
export default function AIDiagnostics({snapshot, locale, disabled=false, onDraft, hasDraft=false}: Props) {
  const en=locale==='en', tr=(ru:string,eng:string)=>en?eng:ru;
  const [source,setSource]=useState<ImportSource>('minecraft-log');
  const [imports,setImports]=useState<Scan[]>([]);
  const [report,setReport]=useState<Report|null>(null);
  const [busy,setBusy]=useState(false);
  const [failed,setFailed]=useState(0);
  const [limit,setLimit]=useState(false);
  const [approved,setApproved]=useState(false);
  const job=useRef(0), reading=useRef(false);
  useEffect(()=>()=>{job.current++;reading.current=false;},[]);
  function invalidate() {setReport(null);setApproved(false);}
  async function addFiles(files: File[]) {
    if (disabled || reading.current || !files.length) return;
    const room=MAX_LOG_FILES-imports.length;
    setLimit(files.length>room);setFailed(0);invalidate();
    if (room<=0) return;
    const id=++job.current;reading.current=true;setBusy(true);
    const results: Scan[]=[];let errors=0;
    try {
      for (const file of files.slice(0,room)) {
        if (job.current!==id) return;
        try {results.push(await scanFile(file,source));} catch {errors++;}
      }
      if(job.current===id) {setImports(old=>[...old,...results].slice(0,MAX_LOG_FILES));setFailed(errors);}
    } finally {if(job.current===id){reading.current=false;setBusy(false);}}
  }
  function clear() {job.current++;reading.current=false;setBusy(false);setImports([]);setFailed(0);setLimit(false);invalidate();}
  const ids=report?findings(report):[];
  return <section className="aiDiagnostics123" aria-label={tr('AI-диагностика','AI diagnostics')}>
    <h3>{tr('AI-диагностика','AI diagnostics')}</h3>
    <p>{tr('Локальная проверка журналов и состояния приложения. Анализ не изменяет файлы, не запускает команды и не отправляет данные автоматически.', 'Local analysis of logs and application state. It does not modify files, run commands or send data automatically.')}</p>
    <p>{tr('Выберите latest.log, crash-report, hs_err_pid или другой текстовый лог. Приложение проверяет только выбранные файлы; у больших логов читаются начало (64 КиБ) и конец (512 КиБ). Исходный текст и имена файлов не сохраняются в отчёте.', 'Select latest.log, a crash report, hs_err_pid or another text log. Only selected files are read; large logs are sampled at the start (64 KiB) and end (512 KiB). Raw text and filenames are not saved in the report.')}</p>
    <div className="toolbar inline">
      <label>{tr('Тип журнала','Log type')} <select value={source} disabled={disabled||busy} onChange={e=>setSource(e.target.value as ImportSource)}>{IMPORT_SOURCES.map(s=><option key={s} value={s}>{names[s][en?1:0]}</option>)}</select></label>
      <label>{tr('Выбрать текстовые файлы','Select text files')} <input type="file" accept=".log,.txt,.out,.err,text/plain" multiple disabled={disabled||busy||imports.length>=MAX_LOG_FILES} onChange={e=>{const selected=Array.from(e.currentTarget.files??[]);e.currentTarget.value='';void addFiles(selected);}}/></label>
    </div>
    <small>{tr('Добавлено журналов','Imported logs')}: {imports.length}/{MAX_LOG_FILES}</small>
    {imports.map((s,i)=><div className="aiDiagnosticSource123" key={i}><span>{names[s.source][en?1:0]} #{i+1} · {s.lines} {tr('строк','lines')}{s.truncated?tr(' · частично',' · sampled'):''}</span><button type="button" disabled={disabled||busy} onClick={()=>{setImports(old=>old.filter((_,index)=>index!==i));invalidate();}}>{tr('Удалить','Remove')}</button></div>)}
    {busy&&<p role="status">{tr('Чтение выбранных журналов…','Reading selected logs…')}</p>}
    {failed>0&&<p role="alert">{tr('Не удалось прочитать текстовые журналы','Could not read text logs')}: {failed}. {tr('Используйте непустой UTF-8 файл без сжатия.','Use a non-empty, uncompressed UTF-8 file.')}</p>}
    {limit&&<p role="alert">{tr('Часть файлов не добавлена: достигнут лимит.','Some files were not added: the limit was reached.')}</p>}
    <div className="toolbar inline"><button type="button" disabled={disabled||busy} onClick={()=>{setReport(localReport(snapshot,imports));setApproved(false);}}>{tr('Анализировать состояние и журналы','Analyze state and logs')}</button><button type="button" disabled={disabled} onClick={clear}>{tr('Очистить диагностику','Clear diagnostics')}</button></div>
    {report&&<>
      <p role="status">{tr('Снимок сформирован. Текущие данные лаунчера могут относиться к предыдущей операции или профилю. Признаки не доказывают причину ошибки.', 'Snapshot created. Launcher data may refer to a previous operation or profile. Indicators do not prove a root cause.')}</p>
      {report.scans.some(s=>s.truncated)&&<p>{tr('Один или несколько источников проанализированы частично. Отсутствие признака не исключает ошибку.', 'One or more sources were sampled. Absence of an indicator does not rule out an error.')}</p>}
      {ids.length===0?<p>{tr('Известные признаки не найдены. Добавьте актуальный лог; это не подтверждение исправности.', 'No known indicators found. Add a current log; this does not establish that the system is healthy.')}</p>:<ul className="aiDiagnosticFindings123">{RULES.filter(r=>ids.includes(r.id)).map(r=><li key={r.id}><strong>{en?r.en:r.ru}</strong><div>{en?r.actionEn:r.actionRu}</div><small>{report.scans.filter(s=>s.evidence.some(e=>e.id===r.id)).map((s,i)=>`${names[s.source][en?1:0]} (${s.evidence.find(e=>e.id===r.id)!.count})`).join(' · ')||tr('Состояние приложения','Application state')}</small></li>)}</ul>}
      <details open><summary>{tr('Точный отчёт для AI (без исходных логов)','Exact AI report (no raw logs)')}</summary><pre>{diagnosticQuestion(report,locale)}</pre></details>
      {onDraft&&<><label className="checkSetting"><input type="checkbox" checked={approved} disabled={disabled} onChange={e=>setApproved(e.target.checked)}/> {tr('Я проверил отчёт. Разрешаю добавить его в поле AI-чата; он будет сохранён в истории только при отправке.', 'I reviewed the report. Allow adding it to the AI composer; it will be stored in history only when sent.')}</label><button type="button" disabled={disabled||!approved||hasDraft} onClick={()=>{if(!approved||hasDraft||disabled)return;onDraft(diagnosticQuestion(report,locale));setApproved(false);}}>{tr('Подготовить запрос AI','Prepare AI request')}</button>{hasDraft&&<small>{tr('Сначала отправьте или очистите текущий черновик чата.','Send or clear the current chat draft first.')}</small>}<small>{tr('Для обращения к OpenAI подтвердите обычное согласие в чате и нажмите «Отправить».', 'To contact OpenAI, confirm the normal chat consent and press Send.')}</small></>}
    </>}
  </section>;
}
