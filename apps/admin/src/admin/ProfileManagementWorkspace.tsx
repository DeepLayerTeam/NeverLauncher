import React, { useEffect, useState } from "react";
import { requestJSON } from "../api/client";
import { GravitImportPanel } from "./GravitImportPanel";

type Preset = {
  id: string;
  name: string;
  description: string;
  loader: string;
  preset: string;
};
type Snapshot = {
  schemaVersion: string;
  revision: number;
  digest: string;
  spec: {
    id: string;
    projectId: string;
    name: string;
    description: string;
    loader: string;
    minecraftVersion?: string;
    loaderVersion?: string;
    javaMajor?: number;
    preset: string;
    isDefault: boolean;
  };
};
type Bundle = { format: string; snapshot: Snapshot };
type Difference = {
  from: Snapshot;
  to: Snapshot;
  changes: {
    field: string;
    from: string | number | boolean;
    to: string | number | boolean;
  }[];
  equal: boolean;
};

export function ProfileManagementWorkspace({
  backendUrl,
  token,
  projectId,
  sourceProfileId,
  onChanged,
  onCreated,
}: {
  backendUrl: string;
  token: string;
  projectId: string;
  sourceProfileId: string;
  onChanged: () => Promise<void>;
  onCreated?: (id: string) => void;
}) {
  const [newId, setNewId] = useState("");
  const [newName, setNewName] = useState("");
  const [sourceRevision, setSourceRevision] = useState("");
  const [preset, setPreset] = useState("vanilla");
  const [presets, setPresets] = useState<Preset[]>([]);
  const [file, setFile] = useState<File | null>(null);
  const [diff, setDiff] = useState<Difference | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const root = `/api/v1/admin/projects/${encodeURIComponent(projectId)}/profiles`;
  const source = `${root}/${encodeURIComponent(sourceProfileId)}`;
  useEffect(() => {
    let live = true;
    if (token)
      requestJSON<{ items: Preset[] }>(
        backendUrl,
        "/api/v1/admin/profile-presets",
        token,
      )
        .then((result) => {
          if (live) setPresets(result.items ?? []);
        })
        .catch((e) => {
          if (live) setError(String(e));
        });
    return () => {
      live = false;
    };
  }, [backendUrl, token]);
  useEffect(() => {
    setDiff(null);
    setNotice("");
    setSourceRevision("");
  }, [projectId, sourceProfileId]);
  const run = async (
    label: string,
    action: () => Promise<unknown>,
    mutation = false,
  ) => {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const result = await action();
      if (mutation) {
        if (result && typeof result === "object" && "profile" in result) {
          const p = (result as { profile?: { id?: string } }).profile;
          if (p?.id) onCreated?.(p.id);
        }
        try {
          await onChanged();
        } catch (reloadError) {
          setNotice(
            `${label}: профиль сохранён, но обновление списка не удалось: ${reloadError instanceof Error ? reloadError.message : String(reloadError)}. Не повторяйте операцию без проверки результата.`,
          );
          return;
        }
      }
      setNotice(`${label}: выполнено`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  const post = (path: string, body: unknown) =>
    requestJSON(backendUrl, path, token, {
      method: "POST",
      body: JSON.stringify(body),
    });
  const rev = sourceRevision ? Number(sourceRevision) : undefined;
  async function importBundle() {
    if (!file) throw new Error("Выберите JSON-файл.");
    if (file.size > 1024 * 1024)
      throw new Error("Файл профиля превышает 1 МБ.");
    const parsed: unknown = JSON.parse(await file.text());
    return post(`${root}/import`, { id: newId, name: newName, bundle: parsed });
  }
  async function exportBundle() {
    const qs = rev ? `?revision=${rev}` : "";
    const bundle = await requestJSON<Bundle>(
      backendUrl,
      `${source}/export${qs}`,
      token,
    );
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(bundle, null, 2) + "\n"], {
        type: "application/json",
      }),
    );
    try {
      const a = document.createElement("a");
      a.href = url;
      a.download = `profile-${sourceProfileId}-r${bundle.snapshot.revision}.json`;
      a.click();
    } finally {
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
  }
  return (
    <article className="subcard">
      <h3>Управление профилями</h3>
      <p>
        Исходный профиль:{" "}
        <strong>{sourceProfileId || "выберите профиль в таблице"}</strong>.
        Новые профили создаются с ревизии 1, без прав владельца и без релизов
        источника.
      </p>
      <label className="field">
        <span>Новый ID</span>
        <input
          value={newId}
          onChange={(e) => setNewId(e.target.value)}
          placeholder="my-profile-copy"
        />
      </label>
      <label className="field">
        <span>Новое название</span>
        <input
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          placeholder="My profile"
        />
      </label>
      <label className="field">
        <span>Ревизия источника (пусто = текущая)</span>
        <input
          type="number"
          min="1"
          value={sourceRevision}
          onChange={(e) => setSourceRevision(e.target.value)}
        />
      </label>
      <div className="buttonRow">
        <button
          disabled={busy || !sourceProfileId || !newId || !projectId}
          onClick={() =>
            run(
              "Клонирование",
              async () => {
                return post(`${source}/clone`, {
                  id: newId,
                  name: newName,
                  ...(rev ? { sourceRevision: rev } : {}),
                });
              },
              true,
            )
          }
        >
          Клонировать
        </button>
        <button
          disabled={busy || !sourceProfileId}
          onClick={() => run("Экспорт", exportBundle)}
        >
          Экспорт JSON
        </button>
        <button
          disabled={busy || !sourceProfileId}
          onClick={() =>
            run("Сравнение ревизий", async () => {
              const q = rev ? `?fromRevision=${rev}` : "";
              setDiff(
                await requestJSON<Difference>(
                  backendUrl,
                  `${source}/diff${q}`,
                  token,
                ),
              );
            })
          }
        >
          Сравнить с текущей
        </button>
      </div>
      <label className="field">
        <span>Импорт Never Profile JSON</span>
        <input
          type="file"
          accept=".json,application/json"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
        />
      </label>
      <div className="buttonRow">
        <button
          disabled={busy || !file || !newId}
          onClick={() => run("Импорт", importBundle, true)}
        >
          Импортировать в новый ID
        </button>
      </div>
      <label className="field">
        <span>Профильный пресет</span>
        <select value={preset} onChange={(e) => setPreset(e.target.value)}>
          {presets.map((p) => (
            <option value={p.id} key={p.id}>
              {p.name} — {p.loader}
            </option>
          ))}
        </select>
      </label>
      <div className="buttonRow">
        <button
          disabled={busy || !newId || !preset}
          onClick={() =>
            run(
              "Создание из пресета",
              async () => {
                return post(`${root}/from-preset`, {
                  id: newId,
                  name: newName,
                  presetId: preset,
                });
              },
              true,
            )
          }
        >
          Создать из пресета
        </button>
      </div>
      {diff && (
        <div role="status">
          <h4>
            Различия: {diff.from.revision} → {diff.to.revision}
          </h4>
          {diff.equal ? (
            <p>Изменений нет.</p>
          ) : (
            <ul>
              {diff.changes.map((c) => (
                <li key={c.field}>
                  {c.field}: {String(c.from)} → {String(c.to)}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      {notice && <p role="status">{notice}</p>}
      {error && <p role="alert">{error}</p>}
      <GravitImportPanel
        backendUrl={backendUrl}
        token={token}
        projectId={projectId}
        onChanged={onChanged}
      />
    </article>
  );
}
