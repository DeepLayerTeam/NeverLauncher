import React, { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type Migration = {
  choice: string | null;
  sourceVersion: string;
  targetVersion: string;
  preservedIds: string[];
  removedIds: string[];
  addedIds: string[];
  presetChanged: boolean;
  blockers: string[];
};
type Diff02410 = {
  addedFiles: string[];
  removedFiles: string[];
  downloadFiles: string[];
  downloadBytesUpperBound: number;
  planSha256: string;
};
type Props = {
  manifest: {
    version: string;
    componentCatalog?: { digest: string };
    projectId: string;
    profileId: string;
  };
  root: string;
  pinnedPublicKey: string;
  transferBusy: boolean;
  installSelection: (choice: string) => Promise<void>;
};

/** The native boundary verifies the old installed release and the new pinned
 * Ed25519 manifest. Imported JSON supplies file paths or JVM arguments. */
export function ComponentPortability02410({
  manifest,
  root,
  pinnedPublicKey,
  transferBusy,
  installSelection,
}: Props) {
  const [automatic, setAutomatic] = useState<Migration | null>(null);
  const [imported, setImported] = useState<Migration | null>(null);
  const [input, setInput] = useState("");
  const [exportText, setExportText] = useState("");
  const [exportStatus, setExportStatus] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [automaticDiff, setAutomaticDiff] = useState<Diff02410 | null>(null);
  const [importedDiff, setImportedDiff] = useState<Diff02410 | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    let cancelled = false;
    setAutomatic(null);
    setImported(null);
    setAutomaticDiff(null);
    setImportedDiff(null);
    setError("");
    invoke<Migration | null>("preview_component_migration_02410", {
      manifest,
      root,
      pinnedPublicKey,
    })
      .then((value) => {
        if (!cancelled) setAutomatic(value);
      })
      .catch((e) => {
        if (!cancelled)
          setError(`Миграция установленного выбора: ${String(e)}`);
      });
    return () => {
      cancelled = true;
    };
  }, [manifest, manifest.componentCatalog?.digest, root, pinnedPublicKey]);
  useEffect(() => {
    let cancelled = false;
    setAutomaticDiff(null);
    if (!automatic?.choice) return;
    invoke<Diff02410>("preview_component_changes_0247", {
      manifest,
      pinnedPublicKey,
      root,
      componentPreset: automatic.choice,
    })
      .then((d) => {
        if (!cancelled) setAutomaticDiff(d);
      })
      .catch((e) => {
        if (!cancelled) setError(`Проверка файлов миграции: ${String(e)}`);
      });
    return () => {
      cancelled = true;
    };
  }, [automatic, manifest, pinnedPublicKey, root]);
  useEffect(() => {
    let cancelled = false;
    setImportedDiff(null);
    if (!imported?.choice) return;
    invoke<Diff02410>("preview_component_changes_0247", {
      manifest,
      pinnedPublicKey,
      root,
      componentPreset: imported.choice,
    })
      .then((d) => {
        if (!cancelled) setImportedDiff(d);
      })
      .catch((e) => {
        if (!cancelled)
          setError(`Проверка импортированных файлов: ${String(e)}`);
      });
    return () => {
      cancelled = true;
    };
  }, [imported, manifest, pinnedPublicKey, root]);
  async function importSelection(data: string) {
    setError("");
    setImported(null);
    if (new TextEncoder().encode(data).length > 1048576)
      throw new Error("Файл выбора превышает 1 МиБ");
    const result = await invoke<Migration>(
      "preview_import_component_selection_02410",
      {
        manifest,
        pinnedPublicKey,
        selectionJson: data,
      },
    );
    setImported(result);
  }
  async function exportSelection() {
    setBusy(true);
    setError("");
    setExportStatus("");
    try {
      const json = await invoke<string>("export_component_selection_02410", {
        root,
        pinnedPublicKey,
      });
      setExportText(json);
      const file = new Blob([json + "\n"], {
        type: "application/json;charset=utf-8",
      });
      const url = URL.createObjectURL(file);
      const link = document.createElement("a");
      link.href = url;
      link.download = `launcher-components-${manifest.projectId}-${manifest.profileId}.json`;
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setExportStatus(
        "Выбор экспортирован. Тот же JSON доступен ниже для ручного сохранения.",
      );
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  async function apply(report: Migration, diff: Diff02410 | null) {
    if (
      !report.choice ||
      !diff ||
      report.blockers.length > 0 ||
      busy ||
      transferBusy
    )
      return;
    setBusy(true);
    setError("");
    try {
      await installSelection(report.choice);
      setAutomatic(null);
      setImported(null);
      setInput("");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  function details(report: Migration, label: string, diff: Diff02410 | null) {
    return (
      <section
        className="componentConfirm0247"
        key={`${label}-${report.sourceVersion}`}
      >
        <h4>
          {label}: {report.sourceVersion} → {report.targetVersion}
        </h4>
        <p>
          Сохранено по ID: {report.preservedIds.length}; исчезло:{" "}
          {report.removedIds.length}; новые обязательные/зависимые:{" "}
          {report.addedIds.length}.
        </p>
        {report.presetChanged && (
          <p>
            Исходный пресет отсутствует в новом релизе; выбран базовый пресет по
            умолчанию.
          </p>
        )}
        {report.preservedIds.length > 0 && (
          <details>
            <summary>Сохранённые компоненты</summary>
            <p>{report.preservedIds.join(", ")}</p>
          </details>
        )}
        {report.removedIds.length > 0 && (
          <p className="componentWarning0247">
            Исчезнувшие компоненты (не удаляют пользовательские файлы):{" "}
            {report.removedIds.join(", ")}
          </p>
        )}
        {report.addedIds.length > 0 && (
          <p>Дополнительно будут включены: {report.addedIds.join(", ")}</p>
        )}
        {diff && (
          <p>
            Файлов добавить: {diff.addedFiles.length}; убрать из managed
            ownership: {diff.removedFiles.length}; загрузить/проверить:{" "}
            {diff.downloadFiles.length}, до{" "}
            {Math.ceil(diff.downloadBytesUpperBound / 1048576)} МиБ (без учёта
            кеша).
          </p>
        )}
        {diff?.removedFiles.length ? (
          <details>
            <summary>Файлы, удаляемые из managed ownership</summary>
            <p>{diff.removedFiles.join(", ")}</p>
          </details>
        ) : null}
        {report.blockers.length > 0 && (
          <div role="alert" className="error">
            Перенос заблокирован: {report.blockers.join("; ")}
          </div>
        )}
        <button
          className="primary"
          disabled={
            !report.choice ||
            !diff ||
            report.blockers.length > 0 ||
            busy ||
            transferBusy
          }
          onClick={() => void apply(report, diff)}
        >
          {busy ? "Применение…" : "Подтвердить перенос и установить"}
        </button>
      </section>
    );
  }
  return (
    <article className="card componentPortability02410">
      <h3>Перенос и резервная копия выбора</h3>
      <p>
        Выбор переносится по подписанным component IDs. Исчезнувшие элементы и
        изменения пресета показываются до установки. Импорт не изменяет
        подписанный релиз.
      </p>
      {automatic &&
        details(automatic, "Перенос с установленного релиза", automaticDiff)}
      <div className="toolbar inline">
        <button
          disabled={busy || transferBusy}
          onClick={() => void exportSelection()}
        >
          Экспорт установленного выбора в JSON
        </button>
        <button
          disabled={busy || transferBusy}
          onClick={() => fileRef.current?.click()}
        >
          Импорт из JSON-файла
        </button>
        <input
          ref={fileRef}
          type="file"
          accept=".json,application/json"
          style={{ display: "none" }}
          onChange={async (e) => {
            const file = e.target.files?.[0];
            e.target.value = "";
            if (!file) return;
            try {
              if (file.size > 1048576) throw new Error("Файл превышает 1 МиБ");
              const data = await file.text();
              setInput(data);
              await importSelection(data);
            } catch (err) {
              setError(String(err));
            }
          }}
        />
      </div>
      <details>
        <summary>Вставить JSON вручную</summary>
        <textarea
          rows={5}
          value={input}
          maxLength={1048576}
          onChange={(e) => setInput(e.target.value)}
          aria-label="JSON выбора компонентов"
        />
        <button
          disabled={busy || transferBusy || !input.trim()}
          onClick={() =>
            void importSelection(input).catch((e) => setError(String(e)))
          }
        >
          Проверить импорт
        </button>
      </details>
      {imported && details(imported, "Импорт выбора", importedDiff)}
      {exportStatus && <p role="status">{exportStatus}</p>}
      {exportText && (
        <details>
          <summary>Экспортированный JSON</summary>
          <textarea
            readOnly
            rows={5}
            value={exportText}
            aria-label="Экспортированный JSON"
          />
        </details>
      )}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
    </article>
  );
}
