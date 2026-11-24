import AIDiagnostics from './AIDiagnostics';
import type {LocalSnapshot} from './ai_diagnostics';
import React, {useEffect, useLayoutEffect, useRef, useState} from 'react';
import {Channel, invoke, isTauri} from '@tauri-apps/api/core';
import {byteLength, buildPrompt, ChatError, emptyHistory, fetchUsage, historyKey, loadHistory, MAX_DIALOGS, MAX_QUESTION_BYTES, MAX_TURNS, newId, saveHistory, streamChat, nativeStream, nativeUsage, type NativeBridge, type NativePacket, type ChatErrorCode, type History, type ProjectContext, type Turn, type Usage} from './ai_chat';
import type {Locale0357} from './desktop_accessibility';

type Props = {backendUrl: string; userId: string; sessionId: string; token: string; projectId: string; profileId: string; context: ProjectContext | null; locale: Locale0357; diagnostics: LocalSnapshot; initialDiagnosticQuestion?: string; onConsumeDiagnosticQuestion?: () => void};
const messages: Record<ChatErrorCode, [string, string]> = {
  sensitive: ['Удалите возможные ключи, токены или пароли из вопроса.', 'Remove possible keys, tokens or passwords from the question.'],
  invalid: ['Некорректный запрос или адрес Backend (требуется HTTPS).', 'Invalid request or Backend address (HTTPS required).'],
  unauthorized: ['Сессия недействительна. Войдите заново.', 'Session invalid. Sign in again.'],
  forbidden: ['Ваша роль не имеет доступа к AI.', 'Your role has no AI access.'],
  limit: ['Достигнут лимит запросов, параллельности или бюджета.', 'Request, concurrency or budget limit reached.'],
  unavailable: ['AI отключён или временно недоступен.', 'AI is disabled or temporarily unavailable.'],
  network: ['Ошибка сети. Проверьте подключение и повторите вручную.', 'Network error. Check your connection and retry manually.'],
  protocol: ['Некорректный ответ AI Gateway.', 'Invalid AI Gateway response.'],
  interrupted: ['Поток прерван без подтверждения завершения.', 'Stream ended without confirmation of completion.'],
  provider: ['Провайдер не завершил генерацию.', 'Provider did not complete generation.'],
  accounting: ['Не удалось подтвердить учёт расходов.', 'Usage accounting could not be confirmed.'],
  revoked: ['Доступ отозван во время генерации.', 'Access revoked during generation.'],
  cancelled: ['Генерация остановлена или истёк тайм-аут.', 'Generation cancelled or timed out.'],
  storage: ['История недоступна, повреждена или превышен лимит хранилища. Удалите ненужные диалоги или очистите историю.', 'History is unavailable, corrupt or storage quota exceeded. Delete unused conversations or clear history.'],
  too_large: ['Превышен допустимый размер запроса или ответа.', 'Request or response size limit exceeded.'],
};
const usd = (n: number) => `$${(n / 1_000_000).toFixed(6)}`;
const errorCode = (e: unknown, signal?: AbortSignal): ChatErrorCode => signal?.aborted ? 'cancelled' : e instanceof ChatError ? e.code : 'network';
const updateTurn = (history: History, dialogId: string, turn: Turn): History => ({version: 1, dialogs: history.dialogs.map(d => d.id === dialogId ? {...d, turns: d.turns.map(t => t.id === turn.id ? turn : t)} : d)});

/** Parent mounts this component with a backend/account/session/project/profile key. */
export default function AIChatWorkspace(props: Props) {
  const {backendUrl, userId, sessionId, token, projectId, profileId, context, locale} = props;
  // Use the native session on installed Desktop; the browser preview uses the regular HTTPS API.
  const native = isTauri();
  const args = {backendUrl, expectedSessionId: sessionId, expectedUserId: userId};
  const bridge: NativeBridge = {
    begin: requestId => invoke<void>('desktop_ai_begin', {requestId}),
    cancel: requestId => invoke<void>('desktop_ai_cancel', {requestId}),
    usage: () => invoke('desktop_ai_usage', args),
    run: (requestId, prompt, onPacket) => {
      const channel = new Channel<NativePacket>();
      channel.onmessage = packet => {onPacket(packet); if (packet.kind === 'end') channel.onmessage = () => {};};
      return invoke<void>('desktop_ai_stream', {...args, requestId, prompt, channel}).catch(e => {channel.onmessage = () => {}; throw e;});
    },
  };
  const en = locale === 'en', tr = (ru: string, eng: string) => en ? eng : ru;
  const [initial] = useState(() => {
    let key = '';
    try {key = historyKey(backendUrl, userId, projectId, profileId); return {key, history: loadHistory(localStorage, key), error: null};}
    catch (e) {return {key, history: emptyHistory(), error: (key ? 'storage' : errorCode(e)) as ChatErrorCode};}
  });
  const [history, setHistory] = useState(initial.history);
  const historyRef = useRef(initial.history);
  const [active, setActive] = useState(props.initialDiagnosticQuestion ? '' : initial.history.dialogs[0]?.id ?? '');
  const [question, setQuestion] = useState(props.initialDiagnosticQuestion ?? '');
  const [attach, setAttach] = useState(false);
  const [consent, setConsent] = useState(false);
  const [storageError, setStorageError] = useState<ChatErrorCode | null>(initial.error);
  const [error, setError] = useState<ChatErrorCode | null>(null);
  const [usageError, setUsageError] = useState<ChatErrorCode | null>(null);
  const [usage, setUsage] = useState<Usage | null>(null);
  const [usageBusy, setUsageBusy] = useState(false);
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<'dialog' | 'all' | null>(null);
  const [live, setLive] = useState<Turn | null>(null);
  const mounted = useRef(false);
  const tokenRef = useRef(token);
  const pending = useRef<{controller: AbortController; dialogId: string; turn: Turn} | null>(null);
  const usageRequest = useRef<AbortController | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const followRef = useRef(true);
  useLayoutEffect(() => {tokenRef.current = token;}, [token]);
  function commit(next: History): boolean {
    try {
      if (!initial.key) throw new ChatError('storage');
      saveHistory(localStorage, initial.key, next);
      historyRef.current = next; setHistory(next); setStorageError(null);
      return true;
    } catch {setStorageError('storage'); return false;}
  }
  async function refreshUsage() {
    usageRequest.current?.abort();
    const controller = new AbortController(); usageRequest.current = controller;
    setUsageBusy(true); setUsageError(null); setUsage(null);
    const timer = window.setTimeout(() => controller.abort(), 15_000);
    try {
      const next = native ? await nativeUsage(bridge, controller.signal) : await fetchUsage(backendUrl, tokenRef.current, controller.signal);
      if (mounted.current && usageRequest.current === controller) setUsage(next);
    } catch (e) {
      if (mounted.current && usageRequest.current === controller) setUsageError(errorCode(e, controller.signal));
    } finally {
      clearTimeout(timer);
      if (mounted.current && usageRequest.current === controller) {usageRequest.current = null; setUsageBusy(false);}
    }
  }
  useLayoutEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      usageRequest.current?.abort(); usageRequest.current = null;
      const job = pending.current;
      if (job) {
        pending.current = null; job.controller.abort();
        // The durable pending record was written before dispatch. On close, retain partial text if possible.
        try {saveHistory(localStorage, initial.key, updateTurn(historyRef.current, job.dialogId, {...job.turn, state: 'interrupted'}));} catch { /* pending is recovered as interrupted next time */ }
      }
    };
  }, []);
  useEffect(() => {if(props.initialDiagnosticQuestion) props.onConsumeDiagnosticQuestion?.(); void refreshUsage();}, []);
  useEffect(() => {
    if (followRef.current && scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [live, history, active]);
  const dialog = history.dialogs.find(d => d.id === active);
  function createDialog() {
    if (pending.current || historyRef.current.dialogs.length >= MAX_DIALOGS || storageError) return;
    const id = newId();
    if (commit({version: 1, dialogs: [{id, createdAt: Date.now(), turns: []}, ...historyRef.current.dialogs]})) {
      setActive(id); setQuestion(''); setError(null); setConfirm(null); followRef.current = true;
    }
  }
  function removeHistory() {
    if (pending.current || !confirm) return;
    const next: History = confirm === 'all' ? emptyHistory() : {version: 1, dialogs: historyRef.current.dialogs.filter(d => d.id !== active)};
    if (commit(next)) {setActive(next.dialogs[0]?.id ?? ''); setConfirm(null); setQuestion(''); setError(null);}
  }
  async function send() {
    if (pending.current || !consent || !usage || usageBusy || storageError || usage.usage.chargedMicroUsd >= usage.budgetMicroUsd) return;
    const text = question.trim(); if (!text) return;
    const current = historyRef.current;
    const existing = current.dialogs.find(d => d.id === active);
    if ((existing && existing.turns.length >= MAX_TURNS) || (!existing && current.dialogs.length >= MAX_DIALOGS)) {setError('storage'); return;}
    let prompt: string;
    try {prompt = buildPrompt(text, existing?.turns ?? [], attach ? context : null).prompt;} catch (e) {setError(errorCode(e)); return;}
    const dialogId = existing?.id ?? newId();
    const turn: Turn = {id: newId(), question: text, answer: '', state: 'pending', at: Date.now()};
    const next: History = {version: 1, dialogs: existing ? current.dialogs.map(d => d.id === dialogId ? {...d, turns: [...d.turns, turn]} : d) : [{id: dialogId, createdAt: Date.now(), turns: [turn]}, ...current.dialogs]};
    // Fail before a paid request if the initial history write cannot be persisted.
    if (!commit(next)) return;
    const controller = new AbortController(); const job = {controller, dialogId, turn}; pending.current = job;
    setActive(dialogId); setQuestion(''); setError(null); setConfirm(null); setLive(turn); setBusy(true); followRef.current = true;
    const timer = window.setTimeout(() => controller.abort(), 110_000);
    const currentJob = () => mounted.current && pending.current === job;
    try {
      const onDelta = (delta: string) => {
        if (!currentJob() || controller.signal.aborted) throw new ChatError('cancelled');
        job.turn = {...job.turn, answer: job.turn.answer + delta}; setLive(job.turn);
      };
      const receipt = native ? await nativeStream(bridge, prompt, controller.signal, onDelta) : await streamChat(backendUrl, tokenRef.current, prompt, controller.signal, onDelta);
      if (currentJob()) job.turn = {...job.turn, receipt, state: 'completed'};
    } catch (e) {
      if (currentJob()) {
        const code = errorCode(e, controller.signal);
        job.turn = {...job.turn, state: ['cancelled', 'interrupted', 'network'].includes(code) ? 'interrupted' : 'failed'};
        setError(code);
      }
    } finally {
      clearTimeout(timer);
      if (currentJob()) {
        pending.current = null;
        const final = updateTurn(historyRef.current, dialogId, job.turn);
        // Keep the complete/partial reply in memory if quota is exhausted, report failure explicitly.
        if (!commit(final)) {historyRef.current = final; setHistory(final);}
        setLive(null); setBusy(false); void refreshUsage();
      }
    }
  }
  let included = 0, promptBytes = 0, fits = false;
  try {if (question.trim()) {const built = buildPrompt(question, dialog?.turns ?? [], attach ? context : null); included = built.included; promptBytes = byteLength(built.prompt); fits = true;}} catch { /* show limit below */ }
  const displayTurns = dialog?.turns.map(t => live?.id === t.id ? live : t) ?? [];
  const full = dialog ? dialog.turns.length >= MAX_TURNS : history.dialogs.length >= MAX_DIALOGS;
  const available = !!usage && !usageBusy && usage.usage.chargedMicroUsd < usage.budgetMicroUsd;
  return <section className="panel aiChat122" aria-label={tr('AI-чат','AI chat')}>
    <header className="aiChatHeader122"><div><h2>{tr('AI-чат','AI chat')}</h2><p>{tr('Помощник по текущему Minecraft-проекту','Assistant for the current Minecraft project')}</p></div><button disabled={usageBusy || busy} onClick={() => void refreshUsage()}>{tr('Обновить бюджет','Refresh budget')}</button></header>
    <p>{tr('Сообщения и включённый контекст отправляются в OpenAI через Backend. Не отправляйте пароли, ключи, персональные данные и приватные логи. Ответы AI могут содержать ошибки.', 'Messages and enabled context are sent to OpenAI via the Backend. Do not send passwords, keys, personal data or private logs. AI answers may be incorrect.')}</p>
    <details className="aiDiagnosticsContainer123"><summary>{tr('Анализ ошибок и журналов','Analyze errors and logs')}</summary>
      <AIDiagnostics snapshot={props.diagnostics} locale={locale} disabled={busy} hasDraft={!!question.trim()} onDraft={text=>{if(pending.current||question.trim())return;setActive('');setQuestion(text);setConsent(false);setAttach(false);setError(null);}}/>
    </details>
    {usage && <div className="aiUsage122" role="status"><strong>{usage.model}</strong><span>{tr('Бюджет','Budget')} ({usage.month} UTC): {usd(usage.usage.chargedMicroUsd)} / {usd(usage.budgetMicroUsd)}</span><span>{tr('Запросы','Requests')}: {usage.usage.requests} · {tr('Неопределённые','Uncertain')}: {usage.usage.uncertainRequests}</span></div>}
    {usageBusy && <p role="status">{tr('Проверка доступа и бюджета…','Checking access and budget…')}</p>}
    {usageError && <p role="alert">{messages[usageError][en ? 1 : 0]}</p>}
    {storageError && <p role="alert">{messages[storageError][en ? 1 : 0]}</p>}
    <div className="aiLayout122">
      <aside className="aiHistory122" aria-label={tr('История диалогов','Conversation history')}>
        <button disabled={busy || !!storageError || history.dialogs.length >= MAX_DIALOGS} onClick={createDialog}>{tr('Новый диалог','New conversation')}</button>
        <small>{history.dialogs.length}/{MAX_DIALOGS} · {tr('На этом устройстве, без шифрования','On this device, unencrypted')}</small>
        {history.dialogs.map(d => <button key={d.id} disabled={busy} aria-pressed={active === d.id} className={active === d.id ? 'activeRow' : ''} onClick={() => {setActive(d.id); setQuestion(''); setError(null); setConfirm(null); followRef.current = true;}}><strong>{d.turns[0]?.question.slice(0, 70) || tr('Новый диалог','New conversation')}</strong><small>{new Date(d.createdAt).toLocaleString(locale)} · {d.turns.length}</small></button>)}
        <button disabled={busy || !dialog} onClick={() => setConfirm('dialog')}>{tr('Удалить диалог','Delete conversation')}</button>
        <button disabled={busy || !initial.key} onClick={() => setConfirm('all')}>{tr('Очистить историю','Clear history')}</button>
        {confirm && <div role="group" aria-label={tr('Подтверждение удаления','Confirm deletion')}><p>{confirm === 'all' ? tr('Удалить историю этого аккаунта и профиля на устройстве?', 'Delete local history for this account and profile?') : tr('Удалить этот диалог?', 'Delete this conversation?')}</p><button disabled={busy} onClick={removeHistory}>{tr('Удалить','Delete')}</button><button onClick={() => setConfirm(null)}>{tr('Отмена','Cancel')}</button></div>}
      </aside>
      <div className="aiConversation122">
        <div ref={scrollRef} className="aiMessages122" onScroll={e => {const el = e.currentTarget; followRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 100;}} aria-label={tr('Сообщения','Messages')}>
          {!displayTurns.length && <p>{tr('Задайте вопрос о настройке Java, сборке, модах или работе лаунчера.', 'Ask about Java settings, builds, mods or the launcher.')}</p>}
          {displayTurns.map(t => <div key={t.id} className="aiTurn122"><article className="aiMessage122"><strong>{tr('Вы','You')}</strong><div>{t.question}</div></article><article className="aiMessage122 aiAnswer122"><strong>AI</strong><div>{t.answer || (t.state === 'pending' ? tr('Ожидание ответа…','Waiting for response…') : tr('Ответ не получен.','No reply received.'))}</div><small>{t.state === 'pending' ? tr('Генерация…','Generating…') : t.state === 'completed' ? tr('Завершено','Completed') : t.state === 'interrupted' ? tr('Прервано','Interrupted') : tr('Ошибка','Failed')}{t.receipt && ` · ${usd(t.receipt.chargedMicroUsd)} · ${t.receipt.inputTokens}/${t.receipt.outputTokens} ${tr('токенов','tokens')}`}</small>{t.state !== 'completed' && t.state !== 'pending' && <button disabled={busy} onClick={() => setQuestion(t.question)}>{tr('Вернуть вопрос в поле ввода','Restore question to composer')}</button>}</article></div>)}
        </div>
        <div role="status" aria-live="polite">{busy ? tr('Идёт генерация.','Generating.') : error ? '' : displayTurns[displayTurns.length - 1]?.state === 'completed' ? tr('Ответ получен.','Response received.') : ''}</div>
        {error && <p role="alert">{messages[error][en ? 1 : 0]} {tr('Запрос автоматически не повторяется; расходы могли быть начислены.', 'The request is not automatically retried; charges may apply.')}</p>}
        <form onSubmit={e => {e.preventDefault(); void send();}} className="aiComposer122">
          <label><input type="checkbox" checked={attach && !!context} disabled={busy || !context} onChange={e => setAttach(e.target.checked)}/> {tr('Добавить контекст текущего проекта','Include current project context')}</label>
          {context ? <details open={attach}><summary>{tr('Данные проекта, доступные для отправки','Project data available to send')}</summary><pre>{JSON.stringify(context, null, 2)}</pre></details> : <small>{tr('Проект не выбран. Доступен общий чат.','No project selected. General chat is available.')}</small>}
          <label><input type="checkbox" checked={consent} disabled={busy} onChange={e => setConsent(e.target.checked)}/> {tr('Разрешаю отправку вопроса, подходящих завершённых сообщений диалога и выбранного контекста в OpenAI.','Allow sending the question, fitting completed conversation turns and selected context to OpenAI.')}</label>
          <label htmlFor="ai-question-122">{tr('Сообщение','Message')}</label>
          <textarea id="ai-question-122" value={question} disabled={busy} rows={4} maxLength={MAX_QUESTION_BYTES} onChange={e => setQuestion(e.target.value)}/>
          <small>{byteLength(question)}/{MAX_QUESTION_BYTES} {tr('байт','bytes')} · {tr('В запросе','In request')}: {promptBytes}/16384 · {tr('Предыдущих пар сообщений','Previous turns')}: {included}</small>
          {question.trim() && !fits && <small role="alert">{messages.too_large[en ? 1 : 0]}</small>}
          {full && <small>{tr('Достигнут предел истории. Создайте новый диалог или удалите старый.','History limit reached. Create a new conversation or delete an old one.')}</small>}
          <div className="toolbar inline"><button type="submit" disabled={busy || !fits || !consent || !available || !!storageError || full}>{tr('Отправить','Send')}</button><button type="button" disabled={!busy} onClick={() => pending.current?.controller.abort()}>{tr('Остановить','Stop')}</button></div>
          {usage && !available && !usageBusy && <small>{tr('Месячный бюджет исчерпан.','Monthly budget exhausted.')}</small>}
        </form>
      </div>
    </div>
  </section>;
}
