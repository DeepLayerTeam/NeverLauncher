import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  HostOperationsClient04111,
  bridgeReady04111,
  hostOperationOutcome04111,
  hostSnapshotFresh04111,
  validHostPending04111,
  type HostAction04111,
  type HostOperation04111,
  type HostPending04111,
  type HostSnapshot04111,
} from "../api/host-operations-04111";
import { durableOwnerKey } from "./owner-recovery-0388";
import { ApiError } from "../api/client";

const pendingKey = (backend: string, user: string, project: string) =>
  durableOwnerKey(backend, user, project, "bridge") + ".host.pending";
function readPending(
  backend: string,
  user: string,
  project: string,
): HostPending04111 | null {
  try {
    const data: unknown = JSON.parse(
      sessionStorage.getItem(pendingKey(backend, user, project)) ?? "null",
    );
    return validHostPending04111(data) ? data : null;
  } catch {
    return null;
  }
}
const datetime = (value?: string) =>
  value && Number.isFinite(Date.parse(value))
    ? new Date(value).toLocaleString()
    : "неизвестно";
const formatBytes = (bytes?: number) =>
  Number.isFinite(bytes) && bytes !== undefined
    ? `${(bytes / 1048576).toFixed(1)} МиБ`
    : "неизвестно";
const describeError = (e: unknown) =>
  e instanceof ApiError && e.status === 403
    ? "Действие запрещено Backend: проверьте глобальное host:process и свежую MFA."
    : e instanceof Error
      ? e.message
      : "Операция недоступна";

type Props = {
  backendUrl: string;
  token: string;
  userId: string;
  projectId: string;
  serverId: string;
  serverName: string;
  allowed: boolean;
};
/** All host actions go through the existing PostgreSQL -> RemoteControl -> real Host Supervisor path.
 * No local or browser-side command execution, and no new key for an uncertain response. */
export function HostOperationsWorkspace04111({
  backendUrl,
  token,
  userId,
  projectId,
  serverId,
  serverName,
  allowed,
}: Props) {
  const api = useMemo(
    () => new HostOperationsClient04111(backendUrl, token),
    [backendUrl, token],
  );
  const [snapshot, setSnapshot] = useState<HostSnapshot04111 | null>(null);
  const [snapshotReadAt, setSnapshotReadAt] = useState<number | null>(null);
  const [history, setHistory] = useState<HostOperation04111[] | null>(null);
  const [historyReadAt, setHistoryReadAt] = useState<number | null>(null);
  const [selectedId, setSelectedId] = useState("");
  const [selected, setSelected] = useState<HostOperation04111 | null>(null);
  const [pending, setPending] = useState<HostPending04111 | null>(() =>
    readPending(backendUrl, userId, projectId),
  );
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(Date.now());
  const sending = useRef(false);
  const scope = `${backendUrl}\0${userId}\0${projectId}`;
  useEffect(() => {
    setPending(readPending(backendUrl, userId, projectId));
    setSelectedId("");
    setSelected(null);
    setHistory(null);
    setHistoryReadAt(null);
    setSnapshot(null);
    setError("");
  }, [scope]);
  // Never show a snapshot from the preceding server after the user changes selection.
  useEffect(() => {
    setSelectedId("");
    setSelected(null);
    setHistory(null);
    setHistoryReadAt(null);
    setSnapshot(null);
    setSnapshotReadAt(null);
    setError("");
  }, [serverId]);
  useEffect(() => {
    if (!allowed || !serverId || !token) return;
    let alive = true;
    async function refresh() {
      // These reads must fail independently: a missing host does not hide the durable journal.
      const [s, h] = await Promise.allSettled([
        api.status(serverId),
        api.list(serverId),
      ]);
      if (!alive) return;
      if (s.status === "fulfilled" && s.value.host?.nodeId) {
        setSnapshot(s.value);
        setSnapshotReadAt(Date.now());
      } else {
        setSnapshot(null);
        setSnapshotReadAt(null);
      }
      if (h.status === "fulfilled" && Array.isArray(h.value)) {
        setHistory(h.value);
        setHistoryReadAt(Date.now());
        setSelected((old) =>
          old && old.serverId === serverId
            ? (h.value.find((op) => op.id === old.id) ?? old)
            : old,
        );
        // Read-only reconciliation: GET can promote accepted to succeeded after
        // JVM/Bridge startup, but it can dispatch another host action.
        if (h.value[0]?.status === "accepted") {
          try {
            const result = await api.get(serverId, h.value[0].id, true);
            if (alive && result.operation?.id === h.value[0].id) {
              setHistory(
                (old) =>
                  old?.map((op) =>
                    op.id === result.operation.id ? result.operation : op,
                  ) ?? null,
              );
              setSelected((old) =>
                old?.id === result.operation.id ? result.operation : old,
              );
            }
          } catch {
            /* journal remains accepted: infer completion */
          }
        }
      } else {
        setHistory(null);
        setHistoryReadAt(null);
        setError(
          "Журнал Host Supervisor недоступен: неизвестные операции нельзя повторять новым ключом.",
        );
      }
    }
    void refresh();
    const interval = window.setInterval(() => {
      if (!document.hidden) void refresh();
    }, 10000);
    return () => {
      alive = false;
      window.clearInterval(interval);
    };
  }, [api, serverId, token, allowed]);
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, []);
  function persist(value: HostPending04111 | null) {
    if (value)
      sessionStorage.setItem(
        pendingKey(backendUrl, userId, projectId),
        JSON.stringify(value),
      );
    else sessionStorage.removeItem(pendingKey(backendUrl, userId, projectId));
    setPending(value);
  }
  const last = history?.[0] ?? null;
  const unresolved =
    history === null ||
    historyReadAt === null ||
    now - historyReadAt >= 25000 ||
    history.some((op) => op.status === "indeterminate") ||
    (!!last && last.status !== "succeeded");
  const pendingForNode = pending?.serverId === serverId ? pending : null;
  const fresh =
    !!snapshot &&
    snapshotReadAt !== null &&
    now - snapshotReadAt < 20000 &&
    hostSnapshotFresh04111(snapshot, now);
  const host = fresh ? snapshot!.host.status : null;
  const gameReady = fresh && bridgeReady04111(snapshot, now);
  const blocked =
    !allowed ||
    busy ||
    sending.current ||
    !!pending ||
    unresolved ||
    (!!selected &&
      selected.serverId === serverId &&
      (selected.status !== "succeeded" ||
        !history?.some((op) => op.id === selected.id))) ||
    !serverId ||
    !userId;
  async function send(original: HostPending04111) {
    if (!allowed || sending.current || busy || !userId) return;
    if (!validHostPending04111(original) || original.serverId !== serverId) {
      setError("Перейдите к серверу исходной незавершённой операции.");
      return;
    }
    const stored = readPending(backendUrl, userId, projectId);
    if (!stored || JSON.stringify(stored) !== JSON.stringify(original)) {
      setError(
        "Исходный ключ операции больше недоступен. Новая операция запрещена.",
      );
      return;
    }
    sending.current = true;
    setBusy(true);
    setNotice("");
    setError("");
    try {
      const response = await api.create(original);
      const op = response.operation;
      if (
        !op?.id ||
        op.serverId !== original.serverId ||
        op.action !== original.action ||
        op.idempotencyKey !== original.idempotencyKey
      )
        throw Error("Backend вернул несоответствующий operation receipt");
      setSelectedId(op.id);
      setSelected(op);
      persist(null);
      setNotice(
        response.idempotentReplay
          ? "Backend вернул ранее сохранённую операцию, без нового исполнения."
          : "Backend сохранил операцию и вернул результат Host Supervisor.",
      );
      const refreshed = await api.list(serverId).catch(() => null);
      if (refreshed) {
        setHistory(refreshed);
        setHistoryReadAt(Date.now());
      }
    } catch (e) {
      setError(
        `${describeError(e)} Исход может быть неизвестен. Восстановление допускается только с сохранённым ключом, без нового физического действия.`,
      );
    } finally {
      sending.current = false;
      setBusy(false);
    }
  }
  function begin(action: HostAction04111) {
    if (blocked) return;
    if (action === "start" && host?.processAlive) {
      setError("JVM уже запущена.");
      return;
    }
    if ((action === "stop" || action === "restart") && !host?.processAlive) {
      setError(
        "Для остановки или перезапуска требуется подтверждённый работающий JVM-процесс.",
      );
      return;
    }
    if (!fresh || !host) {
      setError("Нет свежего подтверждения состояния Host Supervisor.");
      return;
    }
    const prompt = `${action.toUpperCase()} JVM для ${serverName} (${serverId})?\nHost session: ${host.sessionId || "отсутствует"}\nPID: ${host.telemetry?.processId || "неизвестно"}\n\nОперация сохраняется в PostgreSQL до вызова хоста. Результат может остаться неопределённым.`;
    if (!window.confirm(prompt)) return;
    const next = { serverId, action, idempotencyKey: crypto.randomUUID() };
    persist(next); // Durable browser intent BEFORE POST; regenerate on transport failure.
    void send(next);
  }
  async function reconcile(op: HostOperation04111) {
    if (!allowed || busy || sending.current) return;
    setBusy(true);
    setError("");
    try {
      const data = await api.get(op.serverId, op.id, true);
      if (
        data.operation.id !== op.id ||
        data.operation.serverId !== op.serverId
      )
        throw Error("Backend returned wrong operation");
      setSelected(data.operation);
      setSelectedId(data.operation.id);
      const refreshed = await api.list(serverId);
      setHistory(refreshed);
      setHistoryReadAt(Date.now());
    } catch (e) {
      setError("Не удалось прочитать или сверить запись: " + describeError(e));
    } finally {
      setBusy(false);
    }
  }
  if (!allowed)
    return (
      <section className="bridgeSection">
        <h3>Host Supervisor · JVM</h3>
        <p className="bridgeAttention">
          Для управления JVM требуется глобальное право{" "}
          <code>host:process</code>. Проектные игровые роли не дают доступ к
          процессу хоста.
        </p>
      </section>
    );
  if (!serverId) return null;
  const current = selected?.serverId === serverId ? selected : last;
  return (
    <section
      className="bridgeSection"
      aria-label="Реальное управление JVM и Host Supervisor"
    >
      <h3>Host Supervisor · JVM · {serverName}</h3>
      <p className="muted">
        Backend → PostgreSQL journal → TLS RemoteControl → Host Supervisor → OS
        JVM. Игровой heartbeat проверяется отдельно. Команды требуют свежей MFA
        и глобального <code>host:process</code>.
      </p>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {notice && (
        <p className="success" role="status">
          {notice}
        </p>
      )}
      <dl className="bridgeFacts">
        <dt>RemoteControl</dt>
        <dd>
          {fresh
            ? snapshot!.host.nodeId
            : "Нет свежего подтверждения связи с хостом"}
        </dd>
        <dt>JVM</dt>
        <dd>
          {host
            ? host.processAlive
              ? "Запущена (OS-проверка)"
              : "Процесс не обнаружен (OS-проверка)"
            : "неизвестно"}
        </dd>
        <dt>Supervisor</dt>
        <dd>
          {host
            ? host.supervisorAlive
              ? "работает"
              : "не обнаружен"
            : "неизвестно"}
        </dd>
        <dt>PID / Session</dt>
        <dd>
          {host
            ? `${host.telemetry?.processId || "—"} / ${host.sessionId || "—"}`
            : "неизвестно"}
        </dd>
        <dt>RSS / Host RAM</dt>
        <dd>
          {host
            ? `${formatBytes(host.telemetry?.processResidentBytes)} / ${formatBytes(host.telemetry?.hostTotalMemoryBytes)}`
            : "неизвестно"}
        </dd>
        <dt>ServerBridge</dt>
        <dd>
          {gameReady
            ? "Свежий подписанный heartbeat"
            : "неизвестно/не готов; живой JVM-процесс не гарантирует готовность Minecraft"}
        </dd>
        <dt>Наблюдение</dt>
        <dd>
          {fresh ? datetime(snapshot!.observedAt) : "устарело / недоступно"}
        </dd>
      </dl>
      <div className="buttonRow">
        <button
          disabled={blocked || !fresh || !!host?.processAlive}
          onClick={() => begin("start")}
        >
          Запустить JVM
        </button>
        <button
          disabled={blocked || !fresh || !host?.processAlive}
          onClick={() => begin("stop")}
        >
          Остановить JVM
        </button>
        <button
          disabled={blocked || !fresh || !host?.processAlive}
          onClick={() => begin("restart")}
        >
          Перезапустить JVM
        </button>
        <button
          disabled={busy}
          onClick={() => {
            if (current) void reconcile(current);
          }}
        >
          Сверить последнюю операцию
        </button>
      </div>
      {pending && (
        <div className="bridgePending">
          <p className="bridgeAttention">
            Неизвестен исход исходного HTTP-запроса: {pending.action} /{" "}
            {pending.serverId}. Новый ключ создавать нельзя.
          </p>
          <button
            disabled={busy || !pendingForNode}
            onClick={() => {
              if (pendingForNode) void send(pendingForNode);
            }}
          >
            Восстановить запись с исходным ключом (без повторного исполнения)
          </button>
        </div>
      )}
      {current && (
        <article className="subcard" aria-live="polite">
          <h4>
            Операция {current.action}: <code>{current.id}</code>
          </h4>
          <p
            className={
              current.status === "succeeded" ? "success" : "bridgeAttention"
            }
          >
            {hostOperationOutcome04111(current).label}
          </p>
          <dl className="bridgeFacts">
            <dt>Состояние в PostgreSQL</dt>
            <dd>{current.status}</dd>
            <dt>RemoteControl</dt>
            <dd>
              {current.remoteNodeId || "—"} ·{" "}
              {current.remoteReceipt?.state || "без receipt"}
            </dd>
            <dt>Создано / обновлено</dt>
            <dd>
              {datetime(current.createdAt)} / {datetime(current.updatedAt)}
            </dd>
            <dt>Ошибка</dt>
            <dd>{current.error || "—"}</dd>
            <dt>До / после</dt>
            <dd>
              {current.hostBefore?.status?.observedStatus || "неизвестно"} /{" "}
              {current.hostAfter?.status?.observedStatus || "неизвестно"}
            </dd>
          </dl>
          <button disabled={busy} onClick={() => void reconcile(current)}>
            Сверить без повторной команды
          </button>
        </article>
      )}
      <h4>Журнал Host Supervisor (PostgreSQL)</h4>
      {history === null ? (
        <p className="bridgeAttention">
          Не удалось получить журнал. Новые операции заблокированы.
        </p>
      ) : history.length === 0 ? (
        <p className="muted">Операций нет.</p>
      ) : (
        <div className="bridgeNetworkTable">
          <table>
            <thead>
              <tr>
                <th>Операция</th>
                <th>Действие</th>
                <th>Подтверждение</th>
                <th>Время</th>
                <th>Проверка</th>
              </tr>
            </thead>
            <tbody>
              {history.map((op) => (
                <tr key={op.id}>
                  <td>
                    <code>{op.id}</code>
                  </td>
                  <td>{op.action}</td>
                  <td>{op.status}</td>
                  <td>{datetime(op.updatedAt)}</td>
                  <td>
                    <button
                      disabled={busy}
                      onClick={() => {
                        setSelected(op);
                        setSelectedId(op.id);
                        void reconcile(op);
                      }}
                    >
                      {selectedId === op.id ? "Обновить" : "Просмотреть"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="muted">
        При <code>accepted</code> или <code>indeterminate</code> новые действия
        заблокированы в панели. Только read-only сверка с хостом и журналом;
        принудительное снятие неопределённого состояния требует отдельной
        процедуры на Backend.
      </p>
    </section>
  );
}
