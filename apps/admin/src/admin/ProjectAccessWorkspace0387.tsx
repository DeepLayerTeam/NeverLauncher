import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { ApiError, IndeterminateApiError, requestJSON } from '../api/client';
import { assignableRoles0387, membershipChange0387, type ProjectRole0387, type ProjectRoleUser0387 } from './project-membership-0387';

type Props = {
  backendUrl: string; token: string; projectId: string;
  onStepUp: () => Promise<void>;
  onChanged: () => Promise<void>;
};

/** Project role administration uses the existing authenticated user API. No local
 * membership edit is treated as committed until the Backend has saved it. */
export function ProjectAccessWorkspace0387({ backendUrl, token, projectId, onStepUp, onChanged }: Props) {
  const [users, setUsers] = useState<ProjectRoleUser0387[]>([]);
  const [roles, setRoles] = useState<ProjectRole0387[]>([]);
  const [selectedUserId, setSelectedUserId] = useState('');
  const [desiredRole, setDesiredRole] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const selectedUser = users.find(user => user.id === selectedUserId);
  const allowed = useMemo(() => assignableRoles0387(roles), [roles]);
  const currentRole = selectedUser?.projectRoles?.[projectId] ?? '';

  const refresh = useCallback(async () => {
    const [userResponse, roleResponse] = await Promise.all([
      requestJSON<{items:ProjectRoleUser0387[]}>(backendUrl, '/api/v1/admin/users', token),
      requestJSON<{items:ProjectRole0387[]}>(backendUrl, '/api/v1/admin/roles', token),
    ]);
    setUsers(userResponse.items ?? []);
    setRoles(roleResponse.items ?? []);
    setSelectedUserId(previous => userResponse.items?.some(user => user.id === previous) ? previous : '');
  }, [backendUrl, token]);

  useEffect(() => {
    let live = true;
    setUsers([]);setRoles([]);setSelectedUserId('');setError('');setNotice('');
    void Promise.all([
      requestJSON<{items:ProjectRoleUser0387[]}>(backendUrl, '/api/v1/admin/users', token),
      requestJSON<{items:ProjectRole0387[]}>(backendUrl, '/api/v1/admin/roles', token),
    ]).then(([u,r]) => {if(live){setUsers(u.items ?? []);setRoles(r.items ?? []);}})
      .catch(err => {if(live) setError(err instanceof Error ? err.message : String(err));});
    return () => { live = false; };
  }, [backendUrl, token]);

  useEffect(() => { setDesiredRole(currentRole); }, [projectId, selectedUserId, currentRole]);

  async function saveRole() {
    if (!selectedUser || desiredRole === currentRole || !projectId) return;
    const next = membershipChange0387(selectedUser, projectId, desiredRole, allowed);
    const verb = desiredRole ? `назначить ${desiredRole}` : 'удалить проектное назначение';
    if (!window.confirm(`Для ${selectedUser.email} в проекте ${projectId}: ${verb}? Изменение отзовёт прежние сессии пользователя.`)) return;
    setBusy(true);setError('');setNotice('');
    try {
      await requestJSON<ProjectRoleUser0387>(backendUrl, `/api/v1/admin/users/${encodeURIComponent(selectedUser.id)}`, token, {
        method:'PATCH',body:JSON.stringify(next),
      });
      await refresh();
      setNotice(`Назначение для ${selectedUser.email} сохранено на Backend. Проверьте аудит user:project-role.`);
      await onChanged();
    } catch (err) {
      if (err instanceof IndeterminateApiError) {
        setError('Результат изменения неизвестен. Обновите список пользователей и аудит перед повторной попыткой.');
      } else if (err instanceof ApiError && err.status === 409) {
        setError('Права пользователя изменены другим администратором. Обновите список перед повторной попыткой.');
        await refresh().catch(() => undefined);
      } else if (err instanceof ApiError && [401,403,428].includes(err.status)) {
        setError(`${err.message}. Проверьте право users:manage и выполните свежий passkey MFA step-up.`);
      } else setError(err instanceof Error ? err.message : String(err));
    } finally { setBusy(false); }
  }

  return <article className="subcard" aria-label="Доступ операторов к проекту">
    <h3>Доступ операторов к проекту</h3>
    <p className="muted">Назначения действуют только для проекта <strong>{projectId || 'не выбран'}</strong>. Права экземпляра, хоста и Backend не выдаются через projectRoles. Изменение требует свежую phishing-resistant MFA и записывается в аудит.</p>
    <div className="buttonRow"><button disabled={busy} onClick={() => void refresh().catch(e => setError(String(e)))}>Обновить пользователей и роли</button><button disabled={busy} onClick={() => void onStepUp().catch(e => setError(String(e)))}>Подтвердить passkey MFA</button></div>
    <label className="field">Пользователь
      <select value={selectedUserId} onChange={event => setSelectedUserId(event.target.value)} disabled={busy || !projectId}>
        <option value="">Выберите пользователя</option>
        {users.map(user => <option value={user.id} key={user.id}>{user.email} · {user.status} · {user.projectRoles?.[projectId] || 'без роли'}</option>)}
      </select>
    </label>
    {selectedUser && <>
      <p>Глобальная роль: <strong>{selectedUser.roleId}</strong>. Текущая проектная роль: <strong>{currentRole || 'нет'}</strong>.</p>
      {['owner','admin'].includes(selectedUser.roleId) && <p className="muted">У пользователя уже есть глобальные полномочия. Удаление projectRoles не отменяет доступ, который предоставляет глобальная роль.</p>}
      <label className="field">Роль в выбранном проекте
        <select value={desiredRole} disabled={busy || !projectId || selectedUser.status !== 'active'} onChange={event => setDesiredRole(event.target.value)}>
          <option value="">Без проектной роли (убрать назначение)</option>
          {allowed.map(role => <option key={role.id} value={role.id}>{role.name || role.id} ({role.id})</option>)}
          {currentRole && !allowed.some(role => role.id === currentRole) && <option value={currentRole} disabled>Назначенная роль недоступна: {currentRole}</option>}
        </select>
      </label>
      {allowed.find(role => role.id === desiredRole) && <p className="muted">{allowed.find(role => role.id === desiredRole)?.description} · Результирующие права ограничены проектом.</p>}
      <button disabled={busy || !projectId || desiredRole === currentRole || selectedUser.status !== 'active'} onClick={() => void saveRole()}>{busy ? 'Сохранение…' : 'Сохранить назначение на Backend'}</button>
    </>}
    {error && <p role="alert" className="error">{error}</p>}
    {notice && <p role="status" className="success">{notice}</p>}
  </article>;
}
