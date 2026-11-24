import { useRef, useState } from "react";
import { Channel, invoke } from "@tauri-apps/api/core";

type Offer = { currentVersion: string; status: "disabled" | "current" | "available"; version: string | null };
type Progress = { stage: "download" | "verify" | "install"; downloaded: number; total: number | null };

export default function NativeUpdaterPanel() {
  const [offer, setOffer] = useState<Offer | null>(null);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const lock = useRef(false);
  async function check() {
    if (lock.current) return;
    lock.current = true; setBusy(true); setOffer(null); setProgress(null); setMessage("Проверяем обновления…");
    try {
      const result = await invoke<Offer>("native_update_check");
      setOffer(result);
      setMessage(result.status === "disabled" ? "В этой сборке не настроен доверенный источник обновлений." : result.status === "current" ? "Установлена актуальная версия." : "Доступна новая версия. Подпись пакета будет проверена перед установкой.");
    } catch (error) { setMessage(String(error)); }
    finally { lock.current = false; setBusy(false); }
  }
  async function install() {
    if (lock.current || offer?.status !== "available" || !offer.version) return;
    lock.current = true; setBusy(true); setProgress(null); setMessage("Скачиваем подписанный пакет…");
    const channel = new Channel<Progress>();
    channel.onmessage = (event) => {
      setProgress(event);
      setMessage(event.stage === "verify" ? "Проверяем криптографическую подпись и версию…" : event.stage === "install" ? "Передаём проверенный пакет установщику…" : "Скачиваем обновление…");
    };
    try {
      await invoke("native_update_install", { version: offer.version, progress: channel });
      setMessage("Установка запланирована. Launcher будет закрыт и перезапущен установщиком.");
      // Prevent a new action before the native process exits.
    } catch (error) { setMessage(String(error)); setProgress(null); lock.current = false; setBusy(false); }
  }
  return <section className="panel" aria-label="Обновления Launcher">
    <h4>Обновление Launcher</h4>
    {offer && <p>Текущая версия: {offer.currentVersion}{offer.version && ` · Новая версия: ${offer.version}`}</p>}
    <div className="actions">
      <button type="button" disabled={busy} onClick={() => void check()}>Проверить обновления</button>
      {offer?.status === "available" && <button type="button" disabled={busy} onClick={() => void install()}>Скачать и установить {offer.version}</button>}
    </div>
    <p role="status" aria-live="polite">{message}</p>
    {progress?.stage === "download" && <>
      <progress aria-label="Скачивание обновления" max={progress.total || undefined} value={progress.total ? progress.downloaded : undefined} />
      <span> {(progress.downloaded / 1048576).toFixed(1)} МБ</span>
    </>}
    <p>Перед установкой закройте Minecraft и завершите загрузки. Обновление не заменяет игровой профиль или настройки аккаунта.</p>
  </section>;
}
