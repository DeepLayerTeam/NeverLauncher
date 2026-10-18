import React, { useEffect, useState } from 'react';
import { requestJSON } from '../api/client';
import { auditHref, recoveryAdvice } from './lifecycle';

type Session = { id: string; device: string; deviceId?: string; provider?: string; status?: string; riskState?: string; lastIp?: string; lastSeenAt?: string; expiresAt?: string; current?: boolean };
type Device = { id: string; userId: string; name: string; status: string; trustState?: string; keyAlgorithm?: string; keyBinding?: string; hardwareProvider?: string; lastSeenAt?: string; revokedAt?: string; revokedReason?: string; revocationPermanent?: boolean };
type Revocation = { revokedSessions?: number; revokedMinecraftSessions?: number; invalidatedChallenges?: number };

export function SessionsDevicesWorkspace({ backendUrl, token, adminAccess, onCurrentRevoked }: { backendUrl: string; token: string; adminAccess: boolean; onCurrentRevoked: () => void }) {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [result, setResult] = useState('');
  const [query, setQuery] = useState('');
  const [renameId, setRenameId] = useState('');
  const [newName, setNewName] = useState('');
  const [reasonId, setReasonId] = useState('');
  const [reason, setReason] = useState('');
  const api = <T,>(url: string, init?: RequestInit) => requestJSON<T>(backendUrl, url, token, init);
  async function refresh() {
    const [self, managed] = await Promise.all([
      api<{items: Session[]}>('/api/v1/auth/sessions'),
      adminAccess ? api<{items: Device[]}>('/api/v1/admin/auth/devices') : Promise.resolve({items: [] as Device[]}),
    ]);
    setSessions(self.items ?? []); setDevices(managed.items ?? []);
  }
  useEffect(() => {
    let live = true;
    Promise.all([
      requestJSON<{items:Session[]}>(backendUrl, '/api/v1/auth/sessions', token),
      adminAccess ? requestJSON<{items:Device[]}>(backendUrl, '/api/v1/admin/auth/devices', token) : Promise.resolve({items: [] as Device[]}),
    ]).then(([self, managed]) => { if(live) {setSessions(self.items??[]);setDevices(managed.items??[])} }).catch(e => { if(live) setError(e.message); });
    return () => { live = false; };
  }, [backendUrl, token, adminAccess]);
  async function perform(id: string, handler: () => Promise<string>) {
    setBusy(id); setError(''); setResult('');
    try { const message = await handler(); setResult(message); if (id !== "current-session") await refresh(); }
    catch (e) { const reason = e instanceof Error ? e.message : String(e); setError(`${reason} — ${recoveryAdvice(reason)}`); }
    finally { setBusy(''); }
  }
  const revoke = (item: Session) => void perform(item.current ? "current-session" : item.id, async () => {
    if (!window.confirm(`${item.current ? 'Завершить текущую сессию и выйти из Admin' : 'Отозвать сессию'} ${item.device || item.id}?`)) return 'Отменено.';
    await api(`/api/v1/auth/sessions/${encodeURIComponent(item.id)}`, { method: 'DELETE' });
    if (item.current) { onCurrentRevoked(); return 'Текущая сессия отозвана.'; }
    return `Сессия ${item.id} отозвана.`;
  });
  const revokeOthers = () => void perform('others', async () => {
    if (!window.confirm('Отозвать ВСЕ другие сессии текущего пользователя? Другие клиенты потребуют повторного входа.')) return 'Отменено.';
    await api('/api/v1/auth/sessions/revoke-others', { method: 'POST' });
    return 'Другие сессии отозваны.';
  });
  const rename = (item: Session) => void perform(item.id, async () => {
    const name = newName.trim();
    if (!name || name.length > 120) throw new Error('Название должно содержать 1–120 символов.');
    await api(`/api/v1/auth/sessions/${encodeURIComponent(item.id)}`, { method: 'PATCH', body: JSON.stringify({ device: name }) });
    setRenameId(''); setNewName(''); return `Имя сессии ${item.id} изменено.`;
  });
  const revokeDevice = (item: Device) => void perform(item.id, async () => {
    if (reasonId !== item.id || reason.trim().length < 4) throw new Error('Укажите причину отзыва (не меньше 4 символов).');
    if (!window.confirm(`Необратимо отозвать ключ устройства ${item.name || item.id} (${item.id})? Связанные сессии могут завершиться. Повторная регистрация старого ключа будет запрещена.`)) return 'Отменено.';
    const output = await api<Revocation>(`/api/v1/admin/auth/devices/${encodeURIComponent(item.id)}/revoke`, { method: 'POST', body: JSON.stringify({ reason: reason.trim() }) });
    setReasonId(''); setReason('');
    return `Устройство ${item.id} отозвано: сессий ${output.revokedSessions ?? 0}, Minecraft-сессий ${output.revokedMinecraftSessions ?? 0}, challenges ${output.invalidatedChallenges ?? 0}.`;
  });
  const match = (value: string) => value.toLowerCase().includes(query.trim().toLowerCase());
  return <section className="card wide">
    <div className="registryHeading"><div><h2>Сессии и устройства</h2><p className="muted">Свои сессии доступны каждому вошедшему пользователю. Административный отзыв trusted device требует users:manage и свежий phishing-resistant step-up.</p></div><button disabled={!!busy} onClick={() => void perform('refresh', async () => { await refresh(); return 'Состояния обновлены.'; })}>Обновить</button></div>
    {error && <p className="error" role="alert">{error}</p>}{result && <p className="success" role="status">{result} <a href={auditHref('session')}>Посмотреть аудит</a></p>}
    <div className="dataToolbar"><label>Поиск<input type="search" value={query} onChange={e => setQuery(e.target.value)} /></label><button disabled={!!busy || sessions.length < 2} onClick={revokeOthers}>Отозвать другие сессии</button></div>
    <h3>Мои активные сессии ({sessions.length})</h3>
    {sessions.filter(item => match(`${item.id} ${item.device} ${item.deviceId} ${item.provider}`)).map(item => <article className="subcard" key={item.id}>
      <div className="registryHeading"><strong>{item.device || item.deviceId || 'Неизвестное устройство'} {item.current ? '(текущая)' : ''}</strong><span className="badge">{item.status || 'unknown'}</span></div>
      <p className="muted">{item.provider || 'local'} · risk: {item.riskState || 'unknown'} · IP: {item.lastIp || '—'} · последний контакт: {item.lastSeenAt || '—'} · истекает: {item.expiresAt || '—'}</p>
      <p><code>{item.id}</code> · <a href={auditHref(item.id)}>Аудит сессии</a></p>
      <div className="buttonRow"><button disabled={!!busy} onClick={() => { setRenameId(item.id); setNewName(item.device || ''); }}>Переименовать</button><button className="danger" disabled={!!busy} onClick={() => revoke(item)}>{item.current ? 'Завершить и выйти' : 'Отозвать'}</button></div>
      {renameId === item.id && <div className="formGrid"><label className="field">Новое название<input value={newName} maxLength={120} onChange={e => setNewName(e.target.value)} /></label><div className="buttonRow"><button disabled={!!busy || !newName.trim()} onClick={() => rename(item)}>Сохранить</button><button onClick={() => setRenameId('')}>Отмена</button></div></div>}
    </article>)}
    {sessions.length === 0 && <p className="muted">Список сессий пуст или ещё загружается.</p>}
    {adminAccess && <><h3>Trusted devices ({devices.length})</h3>
      {devices.filter(item => match(`${item.id} ${item.userId} ${item.name} ${item.status}`)).map(item => <article className="subcard" key={item.id}>
        <div className="registryHeading"><strong>{item.name || item.id}</strong><span className={`badge ${item.status === 'active' ? 'ok' : 'warn'}`}>{item.status}</span></div>
        <p className="muted">User: {item.userId} · trust: {item.trustState || 'unknown'} · {item.keyAlgorithm || 'key unknown'} · binding: {item.keyBinding || 'unknown'} · last seen: {item.lastSeenAt || '—'}</p>
        {item.revokedAt && <p>Отозвано: {item.revokedAt} · {item.revokedReason || 'причина не указана'}</p>}
        <p><code>{item.id}</code> · <a href={auditHref(item.id)}>Аудит устройства</a></p>
        {item.status === 'active' && <div><button disabled={!!busy} className="danger" onClick={() => { setReasonId(item.id); setReason(''); }}>Отозвать ключ устройства</button>
          {reasonId === item.id && <div className="formGrid"><label className="field">Причина необратимого отзыва<input value={reason} maxLength={240} onChange={e => setReason(e.target.value)} /></label><div className="buttonRow"><button className="danger" disabled={!!busy || reason.trim().length < 4} onClick={() => revokeDevice(item)}>Подтвердить отзыв</button><button onClick={() => setReasonId('')}>Отмена</button></div></div>}
        </div>}
      </article>)}
    </>}
  </section>;
}
