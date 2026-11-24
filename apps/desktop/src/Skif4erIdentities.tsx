import React, { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { browserErrorRu } from "./status-ru";

type Identity = { id: string; provider: string; email?: string; username?: string; displayName?: string };
type Props = { backendUrl: string; sessionId: string; available: boolean };

// Mounted per backend/session, so a late response cannot populate another account's view.
export default function Skif4erIdentities({ backendUrl, sessionId, available }: Props) {
  const [items, setItems] = useState<Identity[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [confirm, setConfirm] = useState<string | null>(null);
  const pending = useRef(false);
  const mounted = useRef(false);
  const args = { backendUrl, expectedSessionId: sessionId };
  async function reload() {
    const next = await invoke<Identity[]>("skif4er_identities", args);
    if (mounted.current) setItems(next);
  }
  async function run(action: () => Promise<void>) {
    if (pending.current) return;
    pending.current = true; setBusy(true); setError(""); setMessage("");
    try { await action(); }
    catch (e) { if (mounted.current) setError(browserErrorRu(e)); }
    finally { pending.current = false; if (mounted.current) setBusy(false); }
  }
  useEffect(() => { mounted.current = true; void run(reload); return () => { mounted.current = false; }; }, [backendUrl, sessionId]);
  const linked = items?.filter(i => i.provider === "skif4er-id") ?? [];
  const local = items?.some(i => i.provider === "local") ?? false;
  return <section className="panel">
    <h2>Связанные идентичности</h2>
    <p>Привязка SkiF4er ID требует недавнего входа в Launcher и подтверждения в браузере. Email не используется для объединения аккаунтов.</p>
    {items === null ? <p>Список ещё не загружен.</p> : items.length === 0 ? <p>Нет связанных идентичностей.</p> : <ul>{items.map(i => <li key={i.id}>
      <strong>{i.provider === "skif4er-id" ? "SkiF4er ID" : i.provider === "local" ? "Локальный аккаунт" : i.provider}</strong>{" — "}{i.displayName || i.username || i.email || "Подключено"}
      {i.provider === "skif4er-id" && <>{confirm === i.id ? <div className="toolbar inline"><span>Отвязать и завершить сессии SkiF4er ID?</span><button className="danger" disabled={busy || !local} onClick={() => void run(async () => {
        await invoke("skif4er_unlink", { ...args, identityId: i.id });
        setConfirm(null); setItems(null); setMessage("SkiF4er ID отвязан."); await reload();
      })}>Подтвердить</button><button disabled={busy} onClick={() => setConfirm(null)}>Отмена</button></div> : <button disabled={busy || !local} onClick={() => setConfirm(i.id)}>Отвязать</button>}</>}
    </li>)}</ul>}
    {linked.length > 0 && <p>Для отвязки необходимо заново войти с локальным паролем. Без резервного входа отвязка запрещена.</p>}
    <div className="toolbar inline"><button disabled={busy} onClick={() => void run(reload)}>Обновить список</button>
    <button disabled={busy || !available || items === null || linked.length > 0} onClick={() => void run(async () => {
      await invoke("skif4er_link", args); setItems(null); setMessage("SkiF4er ID привязан."); await reload();
    })}>Привязать SkiF4er ID</button></div>
    {!available && <p>Провайдер сейчас недоступен. Просмотр и отвязка существующей связи остаются доступны.</p>}
    {busy && <p role="status">Операция выполняется…</p>}{message && <p role="status">{message}</p>}{error && <p role="alert">{error}</p>}
  </section>;
}
