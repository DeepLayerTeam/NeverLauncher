import React, { useEffect, useState } from "react";
import { requestJSON } from "../api/client";
import { TextInput } from "../components/primitives";
import { auditHref, recoveryAdvice } from "./lifecycle";

type RegistryArtifactView = {
  packageIdentity: string;
  sha256: string;
  size: number;
  signatureKeyFingerprint: string;
};
type RegistryVersionView = {
  extensionId: string;
  version: string;
  publisherId: string;
  manifest?: { name?: string; description?: string };
  compatibility?: {
    minLauncher?: string;
    maxLauncher?: string;
    supportedOs?: string[];
    supportedArchitectures?: string[];
  };
  artifact: RegistryArtifactView;
  channels?: string[];
  publishedAt?: string;
  yankedAt?: string;
  yankReason?: string;
};
type RegistrySearchData = {
  schemaVersion?: string;
  count?: number;
  items?: RegistryVersionView[];
};
type ExtensionInstallView = {
  extensionId: string;
  scope: string;
  scopeId?: string;
  version: string;
  desiredVersion: string;
  currentVersion?: string;
  desiredState: string;
  currentState: string;
  enabled: boolean;
  packageIdentity?: string;
  currentPackageIdentity?: string;
  previousVersion?: string;
  generation: number;
  source: string;
  lastError?: string;
  updatedAt?: string;
};
type ExtensionInstallListData = {
  schemaVersion?: string;
  count?: number;
  items?: ExtensionInstallView[];
};
type ExtensionHostView = {
  extensionId: string;
  scope: string;
  scopeId?: string;
  version?: string;
  generation: number;
  pid?: number;
  state: string;
  healthy: boolean;
  restarts: number;
  lastError?: string;
  memoryBytes?: number;
  processCount?: number;
  resourceIsolation: string;
  isolationStatus?: string;
  isolationReasonCodes?: string[];
  effectiveRestrictions?: string[];
  executionTrust?: string;
  processIsolation?: string;
  osSandbox?: string;
  networkSandbox?: string;
  filesystemSandbox?: string;
  lastHeartbeatAt?: string;
};
type ExtensionHostListData = {
  isolationDiagnostics?: {
    platform: string;
    isolationStatus: string;
    reasonCodes: string[];
    enforced: boolean;
    effectiveRestrictions: string[];
  };
  protocolVersion?: string;
  executionTrust?: string;
  resourceIsolation?: string;
  osSandbox?: string;
  networkSandbox?: string;
  filesystemSandbox?: string;
  limits?: Record<string, unknown>;
  items?: ExtensionHostView[];
};

const TOOL_VERSION = __LAUNCHER_VERSION__;
const cancelledOperation = Symbol("cancelled-operation");
export function RegistryWorkspace({
  backendUrl,
  token,
  onError: setError,
  onMessage: setMessage,
  onResult,
  onChanged,
}: {
  backendUrl: string;
  token: string;
  onError: (message: string | null) => void;
  onMessage: (message: string | null) => void;
  onResult: (payload: Record<string, unknown>) => void;
  onChanged: () => Promise<unknown>;
}) {
  const [registryData, setRegistryData] = useState<RegistrySearchData | null>(
    null,
  );
  const [registryQuery, setRegistryQuery] = useState("");
  const [registryChannel, setRegistryChannel] = useState("");
  const [registryLauncherVersion, setRegistryLauncherVersion] =
    useState(TOOL_VERSION);
  const [registryOS, setRegistryOS] = useState("");
  const [registryArch, setRegistryArch] = useState("");
  const [registryPublisherId, setRegistryPublisherId] = useState("");
  const [registryPublisherName, setRegistryPublisherName] = useState("");
  const [registryPublicKey, setRegistryPublicKey] = useState("");
  const [registryPackageFile, setRegistryPackageFile] = useState<File | null>(
    null,
  );
  const [registryPublishChannels, setRegistryPublishChannels] =
    useState("stable");
  const [registryMinLauncher, setRegistryMinLauncher] = useState("");
  const [registryMaxLauncher, setRegistryMaxLauncher] = useState("");
  const [registryPublishOS, setRegistryPublishOS] = useState("");
  const [registryPublishArch, setRegistryPublishArch] = useState("");
  const [extensionScope, setExtensionScope] = useState<"global" | "project">(
    "global",
  );
  const [extensionScopeId, setExtensionScopeId] = useState("");
  const [extensionInstalls, setExtensionInstalls] = useState<
    ExtensionInstallView[]
  >([]);
  const [extensionHosts, setExtensionHosts] = useState<ExtensionHostView[]>([]);
  const [sandboxDiagnostics0311, setSandboxDiagnostics0311] =
    useState<ExtensionHostListData["isolationDiagnostics"]>();
  const [operationBusy, setOperationBusy] = useState(false);
  const [lastOperation, setLastOperation] = useState<{
    label: string;
    output: unknown;
    target: string;
  } | null>(null);

  useEffect(() => {
    loadRegistry().catch((err: Error) => setError(err.message));
    loadExtensionHosts().catch((err: Error) => setError(err.message));
  }, [backendUrl, token]);
  useEffect(() => {
    loadExtensionInstalls().catch((err: Error) => setError(err.message));
  }, [backendUrl, token, extensionScope, extensionScopeId]);

  async function loadRegistry() {
    const params = new URLSearchParams();
    if (registryQuery.trim()) params.set("q", registryQuery.trim());
    if (registryChannel.trim()) params.set("channel", registryChannel.trim());
    if (registryLauncherVersion.trim())
      params.set("launcherVersion", registryLauncherVersion.trim());
    if (registryOS.trim()) params.set("os", registryOS.trim());
    if (registryArch.trim()) params.set("arch", registryArch.trim());
    const suffix = params.toString() ? `?${params.toString()}` : "";
    const data = await requestJSON<RegistrySearchData>(
      backendUrl,
      `/api/v1/admin/extension-registry/extensions${suffix}`,
      token,
    );
    setRegistryData(data);
    onResult(data as unknown as Record<string, unknown>);
    return data;
  }

  async function loadExtensionInstalls() {
    const params = new URLSearchParams();
    params.set("scope", extensionScope);
    if (extensionScope === "project" && extensionScopeId.trim())
      params.set("scopeId", extensionScopeId.trim());
    const data = await requestJSON<ExtensionInstallListData>(
      backendUrl,
      `/api/v1/admin/extension-installs?${params.toString()}`,
      token,
    );
    setExtensionInstalls(data.items ?? []);
    return data;
  }

  async function loadExtensionHosts() {
    const data = await requestJSON<ExtensionHostListData>(
      backendUrl,
      "/api/v1/admin/extension-hosts",
      token,
    );
    setExtensionHosts(data.items ?? []);
    setSandboxDiagnostics0311(data.isolationDiagnostics);
    return data;
  }

  function hostForInstall(item: ExtensionInstallView) {
    return extensionHosts.find(
      (host) =>
        host.extensionId === item.extensionId &&
        host.scope === item.scope &&
        (host.scopeId ?? "") === (item.scopeId ?? ""),
    );
  }

  async function hostAction(
    item: ExtensionInstallView,
    action: "start" | "stop" | "restart",
  ) {
    const params = new URLSearchParams({ scope: item.scope });
    if (item.scopeId) params.set("scopeId", item.scopeId);
    if (
      !confirmAction(
        `Host ${action}: ${item.extensionId}`,
        `${item.scope}:${item.scopeId || "global"} · изменение runtime процесса`,
      )
    )
      return cancelledOperation;
    return requestJSON(
      backendUrl,
      `/api/v1/admin/extension-hosts/${encodeURIComponent(item.extensionId)}/${action}?${params.toString()}`,
      token,
      { method: "POST" },
    );
  }

  async function runRegistryAction(
    label: string,
    fn: () => Promise<unknown>,
    target = "",
  ) {
    if (operationBusy) return;
    setOperationBusy(true);
    setError(null);
    setMessage(null);
    try {
      const result = await fn();
      if (result === cancelledOperation) return; // пользователь отказался; запрос не отправлен
      setLastOperation({ label, output: result, target });
      setMessage(
        `${label}: Сервер вернул результат. Уточните текущее состояние в карточке.`,
      );
      await Promise.all([
        loadRegistry(),
        loadExtensionInstalls(),
        loadExtensionHosts(),
        onChanged(),
      ]);
    } catch (e) {
      const reason = e instanceof Error ? e.message : String(e);
      setError(`${reason}. ${recoveryAdvice(reason)}`);
    } finally {
      setOperationBusy(false);
    }
  }

  function confirmAction(title: string, effect: string): boolean {
    return window.confirm(
      `${title}\n${effect}\nСостояние необходимо проверить после ответа Backend.`,
    );
  }

  async function createRegistryPublisher() {
    if (!registryPublisherId.trim() || !registryPublisherName.trim())
      throw new Error("Укажите ID и название publisher.");
    if (
      !confirmAction(
        `Сохранить publisher ${registryPublisherId}`,
        `Название: ${registryPublisherName}; изменение доверенного реестра`,
      )
    )
      return cancelledOperation;
    return requestJSON(
      backendUrl,
      "/api/v1/admin/extension-registry/publishers",
      token,
      {
        method: "POST",
        body: JSON.stringify({
          id: registryPublisherId.trim(),
          name: registryPublisherName.trim(),
          active: true,
        }),
      },
    );
  }

  async function addRegistryPublisherKey() {
    if (!registryPublisherId.trim() || !registryPublicKey.trim())
      throw new Error(
        "Укажите идентификатор издателя и исходный публичный ключ Ed25519 в Base64.",
      );
    if (
      !confirmAction(
        `Добавить доверенный Ed25519 key для ${registryPublisherId}`,
        "Ключ будет разрешать публикацию подписанных расширений. Проверьте отпечаток ключа до добавления.",
      )
    )
      return cancelledOperation;
    return requestJSON(
      backendUrl,
      `/api/v1/admin/extension-registry/publishers/${encodeURIComponent(registryPublisherId.trim())}/keys`,
      token,
      {
        method: "POST",
        body: JSON.stringify({
          publicKeyBase64: registryPublicKey.trim(),
          active: true,
        }),
      },
    );
  }

  async function publishRegistryArtifact() {
    if (!registryPackageFile)
      throw new Error("Выберите подписанный артефакт .nlext.");
    if (
      !confirmAction(
        `Опубликовать ${registryPackageFile.name}`,
        "Изменится закрытый реестр; подпись проверит сервер",
      )
    )
      return cancelledOperation;
    const body = new FormData();
    body.append("artifact", registryPackageFile);
    if (registryPublisherId.trim())
      body.append("publisher", registryPublisherId.trim());
    if (registryPublishChannels.trim())
      body.append("channels", registryPublishChannels.trim());
    if (registryMinLauncher.trim())
      body.append("minLauncher", registryMinLauncher.trim());
    if (registryMaxLauncher.trim())
      body.append("maxLauncher", registryMaxLauncher.trim());
    if (registryPublishOS.trim()) body.append("os", registryPublishOS.trim());
    if (registryPublishArch.trim())
      body.append("arch", registryPublishArch.trim());
    const response = await fetch(
      `${backendUrl.replace(/\/$/, "")}/api/v1/admin/extension-registry/publish`,
      { method: "POST", headers: { Authorization: `Bearer ${token}` }, body },
    );
    const responsePayload = await response.json().catch(() => ({}));
    if (!response.ok)
      throw new Error(
        responsePayload?.error?.message ??
          `${response.status} ${response.statusText}`,
      );
    return responsePayload.data ?? responsePayload;
  }

  function lifecycleScopePayload() {
    if (extensionScope === "project" && !extensionScopeId.trim())
      throw new Error("Для project scope укажите Project ID.");
    return {
      scope: extensionScope,
      scopeId: extensionScope === "project" ? extensionScopeId.trim() : "",
    };
  }

  async function installRegistryVersion(item: RegistryVersionView) {
    if (
      !confirmAction(
        `Установить ${item.extensionId}@${item.version}`,
        `Scope: ${extensionScope}:${extensionScopeId || "global"}; проверка signature и stage выполняются Backend`,
      )
    )
      return cancelledOperation;
    return requestJSON(
      backendUrl,
      `/api/v1/admin/extension-installs/${encodeURIComponent(item.extensionId)}/install`,
      token,
      {
        method: "POST",
        body: JSON.stringify({
          ...lifecycleScopePayload(),
          version: item.version,
        }),
      },
    );
  }

  async function lifecycleAction(
    item: ExtensionInstallView,
    action: "enable" | "disable" | "uninstall" | "rollback",
  ) {
    if (
      !confirmAction(
        `${action}: ${item.extensionId}`,
        `Scope: ${item.scope}:${item.scopeId || "global"}; версия: ${item.currentVersion || "—"}; необратимые эффекты проверяйте в аудите`,
      )
    )
      return cancelledOperation;
    return requestJSON(
      backendUrl,
      `/api/v1/admin/extension-installs/${encodeURIComponent(item.extensionId)}/${action}`,
      token,
      {
        method: "POST",
        body: JSON.stringify({
          scope: item.scope,
          scopeId: item.scopeId ?? "",
        }),
      },
    );
  }

  async function updateInstalledExtension(item: ExtensionInstallView) {
    const version = window.prompt(
      `Новая версия ${item.extensionId} (оставьте пустым для stable channel)`,
      "",
    );
    if (
      version === null ||
      !confirmAction(
        `Обновить ${item.extensionId}`,
        `Целевая версия: ${version.trim() || "stable"}; область действия: ${item.scope}:${item.scopeId || "global"}`,
      )
    )
      return cancelledOperation;
    const body = version?.trim()
      ? {
          scope: item.scope,
          scopeId: item.scopeId ?? "",
          version: version.trim(),
        }
      : { scope: item.scope, scopeId: item.scopeId ?? "", channel: "stable" };
    return requestJSON(
      backendUrl,
      `/api/v1/admin/extension-installs/${encodeURIComponent(item.extensionId)}/update`,
      token,
      { method: "POST", body: JSON.stringify(body) },
    );
  }

  async function yankRegistryVersion(item: RegistryVersionView) {
    const reason = window.prompt(
      `Причина отзыва версии ${item.extensionId}@${item.version}`,
      "отозвана администратором",
    );
    if (
      !reason ||
      !confirmAction(
        `Отозвать версию ${item.extensionId}@${item.version}`,
        `Исключить версию из новых установок. Причина: ${reason}`,
      )
    )
      return cancelledOperation;
    const result = await requestJSON(
      backendUrl,
      `/api/v1/admin/extension-registry/extensions/${encodeURIComponent(item.extensionId)}/versions/${encodeURIComponent(item.version)}/yank`,
      token,
      { method: "POST", body: JSON.stringify({ reason }) },
    );
    return result;
  }

  async function setRegistryVersionChannel(item: RegistryVersionView) {
    const channel = window.prompt(
      `Канал для ${item.extensionId}@${item.version}`,
      item.channels?.[0] ?? "stable",
    );
    if (
      !channel ||
      !confirmAction(
        `Назначить ${item.extensionId}@${item.version}`,
        `Канал: ${channel}`,
      )
    )
      return cancelledOperation;
    const result = await requestJSON(
      backendUrl,
      `/api/v1/admin/extension-registry/extensions/${encodeURIComponent(item.extensionId)}/channels/${encodeURIComponent(channel)}`,
      token,
      { method: "PUT", body: JSON.stringify({ version: item.version }) },
    );
    return result;
  }

  async function downloadRegistryArtifact(item: RegistryVersionView) {
    const response = await fetch(
      `${backendUrl.replace(/\/$/, "")}/api/v1/admin/extension-registry/extensions/${encodeURIComponent(item.extensionId)}/versions/${encodeURIComponent(item.version)}/artifact`,
      { headers: { Authorization: `Bearer ${token}` } },
    );
    if (!response.ok) {
      const responsePayload = await response.json().catch(() => ({}));
      throw new Error(
        responsePayload?.error?.message ??
          `${response.status} ${response.statusText}`,
      );
    }
    const blob = await response.blob();
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = `${item.extensionId}-${item.version}.nlext`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(href);
    return {
      extensionId: item.extensionId,
      version: item.version,
      size: blob.size,
    };
  }

  const registryItems = registryData?.items ?? [];
  return (
    <section className="card wide registryPanel">
      <div className="registryHeading">
        <div>
          <h2>Реестр расширений {TOOL_VERSION}</h2>
          <p className="muted">
            Private/local registry подписанных immutable .nlext. Publish
            принимает только artifact с доверенным Ed25519 publisher key;
            install повторно проверяет bytes и signature из storage.
          </p>
        </div>
        <span className="badge ok">установка только проверенных пакетов</span>
      </div>
      {lastOperation && (
        <article className="subcard" role="status">
          <strong>{lastOperation.label}</strong>
          <p>Последний ответ Backend:</p>
          <details>
            <summary>Технические детали ответа</summary>
            <pre>
              {JSON.stringify(lastOperation.output, null, 2) ?? "Пустой ответ"}
            </pre>
          </details>
          <a href={auditHref(lastOperation.target || "extension:")}>
            Открыть аудит операции
          </a>
        </article>
      )}
      {operationBusy && (
        <p className="muted" role="status">
          Выполнение операции на сервере…
        </p>
      )}
      <div className="registryToolbar">
        <select
          aria-label="Область действия расширения"
          value={extensionScope}
          onChange={(event) =>
            setExtensionScope(event.target.value as "global" | "project")
          }
        >
          <option value="global">глобально</option>
          <option value="project">проект</option>
        </select>
        {extensionScope === "project" && (
          <input
            aria-label="Область проекта расширения"
            value={extensionScopeId}
            onChange={(event) => setExtensionScopeId(event.target.value)}
            placeholder="ID проекта"
          />
        )}
        <button
          onClick={() =>
            Promise.all([loadExtensionInstalls(), loadExtensionHosts()]).catch(
              (err: Error) => setError(err.message),
            )
          }
        >
          Обновить installs/hosts
        </button>
      </div>
      <div className="registryToolbar">
        <input
          aria-label="Поиск по реестру"
          value={registryQuery}
          onChange={(event) => setRegistryQuery(event.target.value)}
          placeholder="Поиск extension/publisher"
        />
        <input
          aria-label="Канал реестра"
          value={registryChannel}
          onChange={(event) => setRegistryChannel(event.target.value)}
          placeholder="канал: stable"
        />
        <input
          aria-label="Версия лаунчера в реестре"
          value={registryLauncherVersion}
          onChange={(event) => setRegistryLauncherVersion(event.target.value)}
          placeholder="Версия лаунчера"
        />
        <input
          aria-label="ОС реестра"
          value={registryOS}
          onChange={(event) => setRegistryOS(event.target.value)}
          placeholder="ОС: linux"
        />
        <input
          aria-label="Архитектура реестра"
          value={registryArch}
          onChange={(event) => setRegistryArch(event.target.value)}
          placeholder="архитектура: amd64"
        />
        <button
          onClick={() =>
            loadRegistry().catch((err: Error) => setError(err.message))
          }
        >
          Найти
        </button>
      </div>
      <div className="formGrid">
        <article className="subcard">
          <h3>Доверие к издателю</h3>
          <TextInput
            label="ID издателя"
            value={registryPublisherId}
            onChange={setRegistryPublisherId}
          />
          <TextInput
            label="Название"
            value={registryPublisherName}
            onChange={setRegistryPublisherName}
          />
          <label className="field">
            <span>Открытый ключ Ed25519 без упаковки, Base64</span>
            <textarea
              value={registryPublicKey}
              onChange={(event) => setRegistryPublicKey(event.target.value)}
              rows={4}
            />
          </label>
          <div className="buttonRow">
            <button
              onClick={() =>
                runRegistryAction(
                  "Издатель реестра",
                  createRegistryPublisher,
                ).catch((err) => setError(err.message))
              }
            >
              Создать/обновить publisher
            </button>
            <button
              onClick={() =>
                runRegistryAction(
                  "Ключ издателя",
                  addRegistryPublisherKey,
                ).catch((err) => setError(err.message))
              }
            >
              Добавить trusted key
            </button>
          </div>
        </article>
        <article className="subcard">
          <h3>Опубликовать подписанный .nlext</h3>
          <label className="field">
            <span>Артефакт</span>
            <input
              accept=".nlext,application/octet-stream"
              type="file"
              onChange={(event) =>
                setRegistryPackageFile(event.target.files?.[0] ?? null)
              }
            />
          </label>
          <TextInput
            label="Каналы"
            value={registryPublishChannels}
            onChange={setRegistryPublishChannels}
          />
          <TextInput
            label="Мин. версия лаунчера"
            value={registryMinLauncher}
            onChange={setRegistryMinLauncher}
          />
          <TextInput
            label="Макс. версия лаунчера"
            value={registryMaxLauncher}
            onChange={setRegistryMaxLauncher}
          />
          <TextInput
            label="Операционные системы (через запятую)"
            value={registryPublishOS}
            onChange={setRegistryPublishOS}
          />
          <TextInput
            label="Архитектуры (через запятую)"
            value={registryPublishArch}
            onChange={setRegistryPublishArch}
          />
          <div className="buttonRow">
            <button
              disabled={!registryPackageFile}
              onClick={() =>
                runRegistryAction(
                  "Публикация в реестре",
                  publishRegistryArtifact,
                ).catch((err) => setError(err.message))
              }
            >
              Проверить подпись и опубликовать
            </button>
          </div>
        </article>
      </div>
      <section className="registryResults">
        <div className="registryHeading">
          <h3>Опубликованные версии</h3>
          <span className="muted">{registryItems.length} найдено</span>
        </div>
        {registryItems.length === 0 ? (
          <p className="muted">По текущим фильтрам публикаций нет.</p>
        ) : (
          registryItems.map((item) => (
            <article
              className="subcard registryItem"
              key={`${item.extensionId}@${item.version}`}
            >
              <div className="registryHeading">
                <div>
                  <strong>{item.manifest?.name ?? item.extensionId}</strong>
                  <p className="muted">
                    <code>
                      {item.extensionId}@${item.version}
                    </code>{" "}
                    · {item.publisherId}
                  </p>
                </div>
                <div className="registryBadges">
                  {item.channels?.map((channel) => (
                    <span className="badge ok" key={channel}>
                      {channel}
                    </span>
                  ))}
                  {item.yankedAt && <span className="badge warn">отозвано</span>}
                </div>
              </div>
              <p>{item.manifest?.description || "Без описания"}</p>
              <p className="muted">
                Launcher {item.compatibility?.minLauncher || "any"} →{" "}
                {item.compatibility?.maxLauncher || "any"} · OS{" "}
                {(item.compatibility?.supportedOs ?? []).join(", ") || "any"} ·
                arch{" "}
                {(item.compatibility?.supportedArchitectures ?? []).join(
                  ", ",
                ) || "any"}
              </p>
              <p className="registryIdentity">
                <code>{item.artifact.packageIdentity}</code>
              </p>
              {item.yankReason && (
                <p className="error">Отзыв: {item.yankReason}</p>
              )}
              <div className="buttonRow">
                <button
                  disabled={Boolean(item.yankedAt)}
                  onClick={() =>
                    runRegistryAction(
                      "Установка из реестра",
                      () => installRegistryVersion(item),
                      item.extensionId,
                    ).catch((err) => setError(err.message))
                  }
                >
                  Установить verified artifact (staged)
                </button>
                <button
                  disabled={Boolean(item.yankedAt)}
                  onClick={() =>
                    runRegistryAction(
                      "Канал реестра",
                      () => setRegistryVersionChannel(item),
                      item.extensionId,
                    ).catch((err) => setError(err.message))
                  }
                >
                  Назначить канал
                </button>
                <button
                  onClick={() =>
                    runRegistryAction("Загрузка из реестра", () =>
                      downloadRegistryArtifact(item),
                    ).catch((err) => setError(err.message))
                  }
                >
                  Скачать .nlext
                </button>
                <button
                  disabled={Boolean(item.yankedAt)}
                  className="danger"
                  onClick={() =>
                    runRegistryAction(
                      "Отзыв версии из реестра",
                      () => yankRegistryVersion(item),
                      item.extensionId,
                    ).catch((err) => setError(err.message))
                  }
                >
                  Yank
                </button>
              </div>
            </article>
          ))
        )}
      </section>
      <section className="registryResults">
        <div className="registryHeading">
          <h3>Жизненный цикл установки</h3>
          <span className="muted">{extensionInstalls.length} установок</span>
        </div>
        <p className="muted" role="status">
          Изоляция ОС:{" "}
          <strong>
            {sandboxDiagnostics0311?.enforced
              ? "isolated"
              : "не поддерживается / не применяется"}
          </strong>{" "}
          · {sandboxDiagnostics0311?.platform || "неизвестная платформа"} ·{" "}
          {sandboxDiagnostics0311?.reasonCodes?.join(", ") ||
            "нет проверенного заключения"}
          . Подпись пакета не даёт статус trusted. Старые расширения 2.0
          запускаются без OS sandbox.
        </p>
        {extensionInstalls.length === 0 ? (
          <p className="muted">
            Для выбранного scope установок нет. Нажмите «Обновить installs».
          </p>
        ) : (
          extensionInstalls.map((item) => (
            <article
              className="subcard registryItem"
              key={`${item.scope}:${item.scopeId ?? ""}:${item.extensionId}`}
            >
              <div className="registryHeading">
                <div>
                  <strong>{item.extensionId}</strong>
                  <p className="muted">
                    <code>{item.currentVersion || "отсутствует"}</code> · желаемая{" "}
                    <code>{item.desiredVersion}</code> · поколение{" "}
                    {item.generation}
                  </p>
                </div>
                <div className="registryBadges">
                  <span
                    className={`badge ${item.currentState === "enabled" ? "ok" : item.currentState === "absent" ? "warn" : ""}`}
                  >
                    {item.currentState}
                  </span>
                  <span className="badge">
                    {item.scope}
                    {item.scopeId ? `:${item.scopeId}` : ""}
                  </span>
                </div>
              </div>
              <p className="registryIdentity">
                <code>
                  {item.currentPackageIdentity ||
                    item.packageIdentity ||
                    "идентификатор пакета отсутствует"}
                </code>
              </p>
              {item.lastError && <p className="error">{item.lastError}</p>}
              {(() => {
                const host = hostForInstall(item);
                return host ? (
                  <>
                    <p className="muted">
                      Хост: <strong>{host.state}</strong> · доверие{" "}
                      <strong>{host.executionTrust ?? "неизвестно"}</strong> · изоляция
                      ОС {host.osSandbox ?? "none"} · работоспособен{" "}
                      {host.healthy ? "да" : "нет"} · PID {host.pid ?? "—"} ·
                      перезапусков {host.restarts} · RSS{" "}
                      {host.memoryBytes
                        ? `${Math.round(host.memoryBytes / 1024 / 1024)} MiB`
                        : "—"}{" "}
                      · процессов {host.processCount ?? "—"}
                    </p>
                    <p className="muted">
                      Изоляция:{" "}
                      <strong>{host.isolationStatus ?? "неизвестно"}</strong> ·{" "}
                      {host.isolationReasonCodes?.join(", ") ||
                        "нет доказательств"}{" "}
                      · действующие ограничения:{" "}
                      {host.effectiveRestrictions?.join(", ") || "неизвестно"};
                      Сеть {host.networkSandbox ?? "none"}, FS{" "}
                      {host.filesystemSandbox ?? "none"}.
                    </p>
                    {host.lastError && (
                      <p className="error">Хост: {host.lastError}</p>
                    )}
                    <div className="buttonRow">
                      <button
                        disabled={
                          item.currentState !== "enabled" ||
                          host.state === "running"
                        }
                        onClick={() =>
                          runRegistryAction(
                            "Запуск хоста",
                            () => hostAction(item, "start"),
                            item.extensionId,
                          ).catch((err) => setError(err.message))
                        }
                      >
                        Запустить хост
                      </button>
                      <button
                        disabled={
                          !["running", "starting", "stopping"].includes(
                            host.state,
                          )
                        }
                        onClick={() =>
                          runRegistryAction(
                            "Остановка хоста",
                            () => hostAction(item, "stop"),
                            item.extensionId,
                          ).catch((err) => setError(err.message))
                        }
                      >
                        Остановить хост
                      </button>
                      <button
                        disabled={item.currentState !== "enabled"}
                        onClick={() =>
                          runRegistryAction(
                            "Перезапуск хоста",
                            () => hostAction(item, "restart"),
                            item.extensionId,
                          ).catch((err) => setError(err.message))
                        }
                      >
                        Перезапустить хост
                      </button>
                    </div>
                  </>
                ) : item.currentState === "enabled" ? (
                  <p className="muted">
                    Host: backend target не запущен или отсутствует; обновите
                    hosts для актуального состояния.
                  </p>
                ) : null;
              })()}
              <div className="buttonRow">
                <button
                  disabled={
                    item.currentState === "enabled" ||
                    item.currentState === "absent"
                  }
                  onClick={() =>
                    runRegistryAction(
                      "Включение расширения",
                      () => lifecycleAction(item, "enable"),
                      item.extensionId,
                    ).catch((err) => setError(err.message))
                  }
                >
                  Включить
                </button>
                <button
                  disabled={item.currentState !== "enabled"}
                  onClick={() =>
                    runRegistryAction(
                      "Отключение расширения",
                      () => lifecycleAction(item, "disable"),
                      item.extensionId,
                    ).catch((err) => setError(err.message))
                  }
                >
                  Отключить
                </button>
                <button
                  disabled={item.currentState === "absent"}
                  onClick={() =>
                    runRegistryAction(
                      "Обновление расширения",
                      () => updateInstalledExtension(item),
                      item.extensionId,
                    ).catch((err) => setError(err.message))
                  }
                >
                  Обновить
                </button>
                <button
                  onClick={() =>
                    runRegistryAction(
                      "Откат расширения",
                      () => lifecycleAction(item, "rollback"),
                      item.extensionId,
                    ).catch((err) => setError(err.message))
                  }
                >
                  Откатить
                </button>
                <button
                  disabled={item.currentState === "absent"}
                  className="danger"
                  onClick={() =>
                    runRegistryAction(
                      "Удаление расширения",
                      () => lifecycleAction(item, "uninstall"),
                      item.extensionId,
                    ).catch((err) => setError(err.message))
                  }
                >
                  Удалить
                </button>
              </div>
            </article>
          ))
        )}
      </section>
    </section>
  );
}
