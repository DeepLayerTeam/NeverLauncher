import React, { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

type Status = { deviceId?: string; state: string; updatedAt?: string; expiresAt?: string; signalIsProofOfIdentity?: boolean; automaticBan?: boolean };
type Appeal = { id: string; status: string; createdAt: string; reason: string; resolution?: string };

type Props = { backendUrl: string; token: string; deviceId: string };

export function HWIDRisk0299({ backendUrl, token, deviceId }: Props) {
  const [status, setStatus] = useState<Status | null>(null);
  const [appeals, setAppeals] = useState<Appeal[]>([]);
  const [reason, setReason] = useState('');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);

  async function request(path: string, method = 'GET', body?: object): Promise<any> {
    const response = await fetch(`${backendUrl.replace(/\/$/, '')}/api/v1/auth/hwid${path}`, {
      method, headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    const json = await response.json();
    if (!response.ok) throw new Error(json?.error?.message || `HTTP ${response.status}`);
    return json.data;
  }
  async function reload() {
    const [state, history] = await Promise.all([request(''), request('/appeals')]);
    setStatus(state); setAppeals(history.items || []);
  }
  useEffect(() => { void reload().catch(err => setMessage(String(err))); }, [token, deviceId, backendUrl]);
  async function run(action: () => Promise<unknown>, note: string) {
    setBusy(true); setMessage('');
    try { await action(); await reload(); setMessage(note); } catch (err) { setMessage(String(err)); } finally { setBusy(false); }
  }
  return <section className="panel" aria-label="HWID risk">
    <h4>HWID: добровольная оценка риска и восстановление</h4>
    <p>Локально хешируется ограниченный системный сигнал. Исходные идентификаторы не отправляются. Это изменяемый, подделываемый риск-сигнал, а не доказательство личности. Сам по себе он не вызывает бан. Данные наблюдения хранятся до 30 дней; отправка только по нажатию кнопки.</p>
    <p>Устройство: {deviceId}; состояние: <strong>{status?.state || 'неизвестно'}</strong>{status?.expiresAt ? `; срок хранения до ${new Date(status.expiresAt).toLocaleString()}` : ''}</p>
    <div className="toolbar inline">
      <button disabled={busy} onClick={() => void run(async () => { const signal = await invoke<string>('hardware_risk_signal_0299'); await request('/observe', 'POST', { signal }); }, 'Наблюдение принято.')}>Добровольно проверить окружение</button>
      <button disabled={busy} onClick={() => void run(() => request('/confirm', 'POST', {}), 'Новое оборудование подтверждено.')}>Подтвердить замену (Passkey MFA)</button>
      <button disabled={busy} onClick={() => void run(() => request('', 'DELETE'), 'HWID-наблюдения и обращения удалены.')}>Удалить HWID-данные</button>
      <button disabled={busy} onClick={() => void run(reload, 'Состояние обновлено.')}>Обновить статус</button>
    </div>
    {status?.state === 'changed' && <div>
      <p>Окружение изменилось. Можно подтвердить новое оборудование с недавней phishing-resistant MFA либо подать обращение администратору. Старое устройство автоматически не блокируется.</p>
      <label>Причина обращения<textarea value={reason} maxLength={500} onChange={event => setReason(event.target.value)} /></label>
      <button disabled={busy || reason.trim().length < 8} onClick={() => void run(async () => { await request('/appeals', 'POST', { reason: reason.trim() }); setReason(''); }, 'Обращение отправлено.')}>Отправить апелляцию</button>
    </div>}
    {appeals.length > 0 && <div><h4>Обращения</h4>{appeals.map(a => <p key={a.id}>{a.createdAt} · {a.status} · {a.reason}</p>)}</div>}
    <p role="status">{message}</p>
  </section>;
}
