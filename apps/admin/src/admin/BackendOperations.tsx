import React, { useCallback, useEffect, useState } from "react";
import { requestJSON } from "../api/client";
import { navigate } from "./routing";

type Status = {
  instanceId: string;
  version: string;
  commit: string;
  startedAt: string;
  uptimeSeconds: number;
  supervisedRestartEnabled: boolean;
  draining: boolean;
  checks: Record<string, string>;
  operationalConfigRevision: number;
  recentAdminSessions: number;
  sessionMetric: string;
};
type Client = {
  sessionId: string;
  userId: string;
  provider: string;
  lastSeenAt: string;
  expiresAt: string;
};
type Launcher = {
  sessionId: string;
  userId: string;
  profileUuid: string;
  launcherVersion: string;
  lastSeenAt: string;
};
type Clients = {
  adminSessions: Client[];
  launcherSessions: Launcher[];
  adminCount: number;
  launcherCount: number;
  sampledAt: string;
  freshnessSeconds: number;
  limitation: string;
};
export function BackendOperations0289({
  backendUrl,
  token,
}: {
  backendUrl: string;
  token: string;
}) {
  const [status, setStatus] = useState<Status | null>(null);
  const [clients, setClients] = useState<Clients | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [restartKey, setRestartKey] = useState("");
  const [recipient, setRecipient] = useState("");
  const [body, setBody] = useState("");
  const [noticeKey, setNoticeKey] = useState(crypto.randomUUID());
  const refresh = useCallback(async () => {
    const [s, c] = await Promise.all([
      requestJSON<Status>(
        backendUrl,
        "/api/v1/operations/backend/status",
        token,
      ),
      requestJSON<Clients>(
        backendUrl,
        "/api/v1/operations/backend/clients",
        token,
      ),
    ]);
    setStatus(s);
    setClients(c);
  }, [backendUrl, token]);
  useEffect(() => {
    let alive = true;
    void refresh().catch((e) => {
      if (alive) setError(String(e));
    });
    return () => {
      alive = false;
    };
  }, [refresh]);
  async function reload() {
    setBusy(true);
    setError("");
    setInfo("");
    try {
      const result = await requestJSON<{
        appliedRevision: number;
        reloadScope: string;
      }>(backendUrl, "/api/v1/operations/backend/config/reload", token, {
        method: "POST",
      });
      setInfo(
        `Операционные настройки загружены из PostgreSQL, ревизия #${result.appliedRevision}. Статические параметры требуют рестарта.`,
      );
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  async function notify() {
    if (busy || !recipient.trim() || !body.trim()) return;
    setBusy(true);
    setError("");
    setInfo("");
    try {
      const data = await requestJSON<{
        queued: boolean;
        notice: { id: string };
      }>(backendUrl, "/api/v1/operations/backend/notify", token, {
        method: "POST",
        headers: { "Idempotency-Key": noticeKey },
        body: JSON.stringify({
          userId: recipient.trim(),
          message: body.trim(),
        }),
      });
      setInfo(
        `Уведомление ${data.notice.id}: ${data.queued ? "сохранено для доставки" : "уже было сохранено"}. Получатель подтвердит получение через inbox.`,
      );
      setNoticeKey(crypto.randomUUID());
      setBody("");
    } catch (e) {
      setError(
        `${String(e)}. При потере ответа повторите с тем же ключом, не меняя получателя или сообщение.`,
      );
    } finally {
      setBusy(false);
    }
  }
  async function restart() {
    if (!status || confirmation !== `RESTART ${status.instanceId}` || busy)
      return;
    if (
      !window.confirm(
        `Выдать команду завершения именно Backend ${status.instanceId}? Внешний supervisor должен перезапустить процесс.`,
      )
    )
      return;
    // Keep the key in sessionStorage until the outcome is independently checked.
    const storageKey = `launcher.backend-restart:${status.instanceId}`;
    const key =
      restartKey || sessionStorage.getItem(storageKey) || crypto.randomUUID();
    sessionStorage.setItem(storageKey, key);
    setRestartKey(key);
    setBusy(true);
    setError("");
    setInfo("");
    try {
      const result = await requestJSON<{
        state: string;
        rescheduled?: boolean;
        operation: { id: string };
      }>(backendUrl, "/api/v1/operations/backend/restart", token, {
        method: "POST",
        headers: { "Idempotency-Key": key },
        body: JSON.stringify({ instanceId: status.instanceId, confirmation }),
      });
      setInfo(
        `Команда ${result.operation.id}: ${result.state ?? "ранее принята"}. Повтор с тем же ключом не выполняет действие ещё раз.`,
      );
    } catch (e) {
      setError(
        `${String(e)}. Исход команды может быть неизвестен: не создавайте новый ключ до проверки supervisor и аудита.`,
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="card wide">
      <h2>Backend Operations · {__LAUNCHER_VERSION__}</h2>
      <p className="muted">
        Управление самим Backend, не Minecraft-серверами или процессами
        произвольного хоста. Требуется глобальное backend:control.
      </p>
      <div className="buttonRow">
        <button
          disabled={busy}
          onClick={() => void refresh().catch((e) => setError(String(e)))}
        >
          Обновить состояние
        </button>
        <button disabled={busy} onClick={() => void reload()}>
          Reload безопасных настроек (MFA)
        </button>
      </div>
      {status ? (
        <>
          <p>
            Версия: <strong>{status.version}</strong> · commit:{" "}
            <code>{status.commit}</code> · uptime: {status.uptimeSeconds} с
          </p>
          <p>
            Runtime identity: <code>{status.instanceId}</code> · config
            revision: #{status.operationalConfigRevision}
          </p>
          <p>
            Supervised restart:{" "}
            <strong>
              {status.supervisedRestartEnabled ? "включён" : "отключён"}
            </strong>{" "}
            · draining: {status.draining ? "да" : "нет"}
          </p>
          <table className="table">
            <thead>
              <tr>
                <th>Проверка</th>
                <th>Результат</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(status.checks).map(([k, v]) => (
                <tr key={k}>
                  <td>{k}</td>
                  <td>{v}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <h3>Контролируемый restart</h3>
          <p className="muted">
            Только при наличии внешнего service manager и PostgreSQL-журнала.
            Требуется свежая phishing-resistant MFA. Повтор не должен создавать
            новую команду.
          </p>
          <label className="field">
            Точное подтверждение: <code>RESTART {status.instanceId}</code>
            <input
              value={confirmation}
              onChange={(e) => setConfirmation(e.target.value)}
              autoComplete="off"
            />
          </label>
          <button
            disabled={
              busy ||
              status.draining ||
              !status.supervisedRestartEnabled ||
              confirmation !== `RESTART ${status.instanceId}`
            }
            onClick={() => void restart()}
          >
            Запросить graceful restart
          </button>
        </>
      ) : (
        <p>Backend status недоступен.</p>
      )}
      <h3>Наблюдаемые сессии</h3>
      <p className="muted">
        Admin и Minecraft launcher sessions с lastSeenAt не старше пяти минут.
        Это не открытые TCP-соединения и не количество игроков на игровых
        серверах.
      </p>
      {clients && (
        <>
          <p>
            Admin: {clients.adminCount} · Launcher: {clients.launcherCount} · на{" "}
            {clients.sampledAt} (не более 100 каждого типа)
          </p>
          <table className="table">
            <thead>
              <tr>
                <th>Session</th>
                <th>User</th>
                <th>Provider</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {clients.adminSessions.map((it) => (
                <tr key={it.sessionId}>
                  <td>
                    <code>{it.sessionId}</code>
                  </td>
                  <td>{it.userId}</td>
                  <td>{it.provider}</td>
                  <td>{it.lastSeenAt}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <h4>Launcher sessions</h4>
          <table className="table">
            <thead>
              <tr>
                <th>Session</th>
                <th>User</th>
                <th>Profile UUID</th>
                <th>Launcher version</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {clients.launcherSessions.map((it) => (
                <tr key={it.sessionId}>
                  <td>
                    <code>{it.sessionId}</code>
                  </td>
                  <td>{it.userId}</td>
                  <td>{it.profileUuid}</td>
                  <td>{it.launcherVersion}</td>
                  <td>{it.lastSeenAt}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      <h3>Уведомить пользователя</h3>
      <p className="muted">
        Durable inbox для авторизованных клиентов; не игровой broadcast и не
        push-соединение.
      </p>
      <label className="field">
        User ID
        <input
          value={recipient}
          maxLength={128}
          onChange={(e) => {
            setRecipient(e.target.value);
            setNoticeKey(crypto.randomUUID());
          }}
        />
      </label>
      <label className="field">
        Сообщение
        <textarea
          value={body}
          maxLength={512}
          onChange={(e) => {
            setBody(e.target.value);
            setNoticeKey(crypto.randomUUID());
          }}
        />
      </label>
      <button
        disabled={busy || !recipient.trim() || !body.trim()}
        onClick={() => void notify()}
      >
        Отправить уведомление (MFA)
      </button>
      <h3>Связанные рабочие операции</h3>
      <div className="buttonRow">
        <button onClick={() => navigate("config")}>
          Validate / apply / rollback конфигурации
        </button>
        <button onClick={() => navigate("job-monitor")}>
          Build / publish jobs
        </button>
        <button onClick={() => navigate("extensions-manager")}>
          Extension lifecycle
        </button>
        <button onClick={() => navigate("devices")}>
          Token / session lifecycle
        </button>
        <button onClick={() => navigate("audit")}>Журнал аудита</button>
      </div>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {info && <p className="success">{info}</p>}
    </section>
  );
}
