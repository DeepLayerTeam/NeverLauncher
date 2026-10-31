import React, { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type Settings = {
  fullscreen?: boolean | null;
  screenWidth?: number | null;
  screenHeight?: number | null;
};
type Preview = {
  source: string;
  projectId: string;
  profileId: string;
  channel: string;
  releaseVersion: string;
  selectedPreset: string;
  matchedFiles: number;
  missingFiles: number;
  matchedBytes: number;
  matchedPaths: string[];
  optionalComponentCandidates: string[];
  suggestedSettings: Settings;
  warning: string;
};
type Adopted = {
  cachedFiles: number;
  cachedBytes: number;
  unavailableFiles: number;
  optionalComponentCandidates: string[];
  suggestedSettings: Settings;
  message: string;
};

type Props = {
  manifest: any;
  pinnedPublicKey: string;
  componentPreset: string;
  transferBusy: boolean;
  applyDisplayPreferences: (patch: Settings) => Promise<void>;
  onAdopted: () => void;
};

/** Gravit directories are local, untrusted input. No credentials, mods or unknown executables are ever imported. */
export default function PlayerMigration0339({
  manifest,
  pinnedPublicKey,
  componentPreset,
  transferBusy,
  applyDisplayPreferences,
  onAdopted,
}: Props) {
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [source, setSource] = useState("");
  const [preview, setPreview] = useState<Preview | null>(null);
  const [result, setResult] = useState<Adopted | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [copyPreferences, setCopyPreferences] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    void invoke<string[]>("player_migration_discover_0339")
      .then((paths) => {
        if (!cancelled) setSuggestions(paths);
      })
      .catch((err) => {
        if (!cancelled) setError(String(err));
      });
    return () => {
      cancelled = true;
    };
  }, []);
  useEffect(() => {
    setPreview(null);
    setConfirmed(false);
    setResult(null);
  }, [source, manifest, componentPreset, pinnedPublicKey]);

  const args = () => ({
    manifest,
    pinnedPublicKey,
    legacyRoot: source.trim(),
    componentPreset: componentPreset || null,
  });
  const valid = Boolean(
    manifest?.signature && pinnedPublicKey && source.trim(),
  );
  async function inspect() {
    setBusy(true);
    setError("");
    setResult(null);
    try {
      setPreview(
        await invoke<Preview>("player_migration_preview_0339", args()),
      );
    } catch (err) {
      setPreview(null);
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }
  async function adopt() {
    if (!confirmed || !preview || !valid) return;
    setBusy(true);
    setError("");
    try {
      const output = await invoke<Adopted>(
        "player_migration_adopt_0339",
        args(),
      );
      setResult(output);
      if (copyPreferences) {
        try {
          await applyDisplayPreferences(output.suggestedSettings);
        } catch (settingsError) {
          setError(
            `Кэш перенесён, но настройки экрана не удалось сохранить: ${String(settingsError)}`,
          );
        }
      }
      onAdopted();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="panel">
      <h3>Переход с GravitLauncher — Player Migration Assistant 0.33.9</h3>
      <p>
        Установите Launcher только по официальной ссылке владельца проекта и
        проверьте издателя установщика. Ассистент не принимает неподписанные
        сборки: повторно используются только файлы, совпадающие с подписанным
        Ed25519 manifest Never для текущего проекта, профиля и выбранного набора
        компонентов.
      </p>
      {!manifest?.signature && (
        <p role="alert">
          Сначала загрузите подписанный профиль Launcher в разделе «Профиль».
        </p>
      )}
      <label>
        Прежний каталог GravitLauncher / Minecraft
        <input
          value={source}
          onChange={(e) => setSource(e.target.value)}
          placeholder="C:\\Games\\GravitLauncher или /home/user/.minecraft"
        />
      </label>
      {suggestions.length > 0 && (
        <div className="toolbar inline">
          {suggestions.map((path) => (
            <button key={path} type="button" onClick={() => setSource(path)}>
              {path}
            </button>
          ))}
        </div>
      )}
      <p>
        Каталог можно указать вручную. Сканируются только пути текущего профиля;
        исходная папка остаётся неизменной.
      </p>
      <div className="toolbar inline">
        <button
          disabled={!valid || busy || transferBusy}
          onClick={() => void inspect()}
        >
          Проверить старые файлы
        </button>
      </div>
      {preview && (
        <>
          <p>
            <strong>Совпадает:</strong> {preview.matchedFiles} файлов (
            {(preview.matchedBytes / 1048576).toFixed(1)} МиБ).{" "}
            <strong>Не найдено:</strong> {preview.missingFiles}. Остальное
            загрузится обычным установщиком Never.
          </p>
          <p>
            Проект: {preview.projectId}; профиль: {preview.profileId}; канал:{" "}
            {preview.channel}; релиз: {preview.releaseVersion}.
          </p>
          <p>
            Обнаруженные кандидаты optional mods (не выбираются автоматически):{" "}
            {preview.optionalComponentCandidates.join(", ") || "нет"}. Выбор
            пресета выполняется через обычный интерфейс компонентов.
          </p>
          <details>
            <summary>Совпавшие пути</summary>
            <pre>{preview.matchedPaths.join("\n")}</pre>
          </details>
          <label className="checkSetting">
            <input
              type="checkbox"
              checked={copyPreferences}
              onChange={(e) => setCopyPreferences(e.target.checked)}
            />{" "}
            После переноса предложить сохранённые настройки экрана из Minecraft
            options.txt (только fullscreen и разрешение)
          </label>
          <label className="checkSetting">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
            />{" "}
            Подтверждаю перенос только проверенного содержимого в Never cache;
            повторный вход и регистрация устройства обязательны
          </label>
          <div className="toolbar inline">
            <button
              className="primary"
              disabled={
                !confirmed ||
                !preview.matchedFiles ||
                busy ||
                transferBusy ||
                Boolean(result)
              }
              onClick={() => void adopt()}
            >
              Использовать проверенный кэш
            </button>
          </div>
        </>
      )}
      {result && (
        <p role="status">
          Перенесено в кэш: {result.cachedFiles} файлов,{" "}
          {(result.cachedBytes / 1048576).toFixed(1)} МиБ. Запустите обычную
          установку/восстановление, затем выполните вход. Исходные данные не
          удалены.
        </p>
      )}
      {error && <p role="alert">{error}</p>}
      <p>
        <small>
          Не копируются пароли, сессии, приватные ключи, Guard-attestation,
          Java-параметры, сторонние JAR вне подписанного manifest или
          произвольные конфигурации. Проверка установщика и его подписи остаётся
          задачей официального канала распространения проекта.
        </small>
      </p>
    </section>
  );
}
