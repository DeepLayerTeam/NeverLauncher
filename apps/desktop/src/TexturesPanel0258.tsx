import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { TexturePreview0258 } from "./TexturePreview0258";
import {
  OfficialMinecraftClient0257,
  type OfficialProfile0257,
} from "./official_minecraft_0257";
import {
  TextureServiceClient0258,
  TextureServiceError0258,
  textureAssignment0258,
  textureRevision0258,
  validateTextureFile0258,
  safeOfficialTextureURL0258,
  type TextureAssignment0258,
  type TextureItem0258,
  type TextureIdentity0258,
  type TextureKind0258,
  type SkinModel0258,
  type TextureVisibility0258,
} from "./texture_service_0258";

function usePrivatePNG0258(
  client: TextureServiceClient0258 | null,
  kind: TextureKind0258,
  digest?: string,
) {
  const [url, setURL] = useState("");
  useEffect(() => {
    setURL("");
    if (!client || !digest) return;
    const controller = new AbortController();
    let object = "";
    void client
      .preview(kind, digest, controller.signal)
      .then((src) => {
        if (controller.signal.aborted) {
          URL.revokeObjectURL(src);
          return;
        }
        object = src;
        setURL(src);
      })
      .catch(() => {
        if (!controller.signal.aborted) setURL("");
      });
    return () => {
      controller.abort();
      if (object) URL.revokeObjectURL(object);
    };
  }, [client, kind, digest]);
  return url;
}
function SavedCard0258({
  item,
  client,
  active,
  busy,
  onChoose,
  onDelete,
  onPreview,
}: {
  item: TextureItem0258;
  client: TextureServiceClient0258;
  active: boolean;
  busy: boolean;
  onChoose: () => void;
  onDelete: () => void;
  onPreview: () => void;
}) {
  const src = usePrivatePNG0258(client, item.kind, item.digest);
  return (
    <article className={"textureCard0258 " + (active ? "chosen" : "")}>
      <button
        type="button"
        className="textureImageButton0258"
        onClick={onPreview}
        disabled={!src}
        aria-label={`Просмотреть ${item.kind} ${item.digest.slice(0, 8)}`}
      >
        {src ? <img src={src} alt="" loading="lazy" /> : <span>PNG</span>}
      </button>
      <div className="textureCardDetails0258">
        <strong>
          {item.kind === "skin" ? "Скин" : "Плащ"} ·{" "}
          {item.model === "slim" ? "Slim" : "Classic"}
        </strong>
        <small>
          {item.width}×{item.height} · {Math.ceil(item.bytes / 1024)} КиБ
        </small>
        <small title={item.digest}>{item.digest.slice(0, 12)}…</small>
        {active && <small className="textureActive0258">Активен</small>}
      </div>
      <div className="textureCardActions0258">
        <button type="button" disabled={busy} onClick={onChoose}>
          {active ? "Выбрать ещё раз" : "Выбрать"}
        </button>
        <button
          type="button"
          disabled={busy}
          className="danger"
          onClick={onDelete}
        >
          Удалить
        </button>
      </div>
    </article>
  );
}

export function TexturesPanel0258({
  backendUrl,
  token,
  officialClient,
  officialProfile,
  onOfficialProfile,
  identityMode,
}: {
  backendUrl: string;
  token: string;
  officialClient: OfficialMinecraftClient0257 | null;
  officialProfile: OfficialProfile0257 | null;
  onOfficialProfile: (p: OfficialProfile0257 | null) => void;
  identityMode: "local" | "official";
}) {
  const client = useMemo(
    () =>
      token && backendUrl
        ? new TextureServiceClient0258(backendUrl, token)
        : null,
    [backendUrl, token],
  );
  const [realm, setRealm] = useState<"local" | "official">(identityMode);
  const [identity, setIdentity] = useState<TextureIdentity0258 | null>(null);
  const [saved, setSaved] = useState<TextureItem0258[]>([]);
  const [kind, setKind] = useState<TextureKind0258>("skin");
  const [model, setModel] = useState<SkinModel0258>("classic");
  const [visibility, setVisibility] = useState<TextureVisibility0258>("public");
  const [file, setFile] = useState<File | null>(null);
  const [filePreview, setFilePreview] = useState("");
  const [selected, setSelected] = useState<TextureItem0258 | null>(null);
  const [offset, setOffset] = useState(0);
  const [importUrl, setImportUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<number | null>(null);
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [history, setHistory] = useState<
    Array<{ revision: number; event: string; createdAt: string }>
  >([]);
  const [showHistory, setShowHistory] = useState(false);
  const operation = useRef<AbortController | null>(null);
  const loadId = useRef(0);

  useEffect(() => setRealm(identityMode), [identityMode]);
  useEffect(() => {
    setSelected(null);
    setFile(null);
    setOffset(0);
    setShowHistory(false);
  }, [kind, realm]);
  useEffect(() => {
    if (!file) {
      setFilePreview("");
      return;
    }
    const object = URL.createObjectURL(file);
    setFilePreview(object);
    return () => URL.revokeObjectURL(object);
  }, [file]);
  useEffect(
    () => () => {
      operation.current?.abort();
    },
    [client, officialClient],
  );

  const refresh = useCallback(
    async (signal?: AbortSignal) => {
      if (!client) return;
      const id = ++loadId.current;
      const [mine, library] = await Promise.all([
        client.identity(signal),
        client.library(signal),
      ]);
      if (signal?.aborted || id !== loadId.current) return;
      setIdentity(mine);
      setSaved(library);
    },
    [client],
  );
  useEffect(() => {
    const controller = new AbortController();
    setIdentity(null);
    setSaved([]);
    setError("");
    setSelected(null);
    if (client)
      void refresh(controller.signal).catch((e) => {
        if (!controller.signal.aborted)
          setError(String(e instanceof Error ? e.message : e));
      });
    return () => {
      controller.abort();
      loadId.current++;
    };
  }, [client, refresh]);
  useEffect(() => {
    if (!client || !showHistory || realm !== "local") return;
    const controller = new AbortController();
    void client
      .history(kind, controller.signal)
      .then((v) => {
        if (!controller.signal.aborted) setHistory(Array.isArray(v) ? v : []);
      })
      .catch((e) => {
        if (!controller.signal.aborted) setError(String(e));
      });
    return () => controller.abort();
  }, [client, kind, showHistory, realm, identity]);

  const assigned = identity
    ? textureAssignment0258(identity.items, kind)
    : undefined;
  const revision = identity ? textureRevision0258(identity.items, kind) : 0;
  const currentSkin = identity
    ? textureAssignment0258(identity.items, "skin")
    : undefined;
  const currentCape = identity
    ? textureAssignment0258(identity.items, "cape")
    : undefined;
  useEffect(() => {
    if (realm === "local" && assigned) {
      setModel(assigned.model);
      setVisibility(assigned.visibility);
    }
  }, [realm, kind, assigned?.id, assigned?.revision]);
  const shown = useMemo(
    () =>
      saved
        .filter((s) => s.kind === kind)
        .sort((a, b) =>
          (b.lastSelectedAt || b.createdAt).localeCompare(
            a.lastSelectedAt || a.createdAt,
          ),
        ),
    [saved, kind],
  );
  const page = shown.slice(offset, offset + 12);
  const previewSkin = usePrivatePNG0258(
    client,
    "skin",
    realm === "local"
      ? selected?.kind === "skin"
        ? selected.digest
        : currentSkin?.active
          ? currentSkin.blobDigest
          : undefined
      : undefined,
  );
  const previewCape = usePrivatePNG0258(
    client,
    "cape",
    realm === "local"
      ? selected?.kind === "cape"
        ? selected.digest
        : currentCape?.active
          ? currentCape.blobDigest
          : undefined
      : undefined,
  );
  const officialSkin =
    officialProfile?.skins.find((s) => s.state === "ACTIVE") ||
    officialProfile?.skins[0];
  const officialCape = officialProfile?.capes.find((c) => c.state === "ACTIVE");
  const skinURL =
    realm === "official"
      ? kind === "skin" && filePreview
        ? filePreview
        : safeOfficialTextureURL0258(officialSkin?.url || "")
      : kind === "skin" && filePreview
        ? filePreview
        : previewSkin;
  const capeURL =
    realm === "official"
      ? safeOfficialTextureURL0258(officialCape?.url || "")
      : kind === "cape" && filePreview
        ? filePreview
        : previewCape;
  const renderModel =
    realm === "official"
      ? kind === "skin" && filePreview
        ? model
        : officialSkin?.variant?.toLowerCase() === "slim"
          ? "slim"
          : "classic"
      : kind === "skin" && filePreview
        ? model
        : selected?.kind === "skin"
          ? selected.model
          : currentSkin?.model || "classic";

  async function perform(
    task: (signal: AbortSignal) => Promise<void>,
    message: string,
  ) {
    if (busy) return;
    const controller = new AbortController();
    operation.current = controller;
    setBusy(true);
    setError("");
    setStatus("");
    setProgress(null);
    try {
      await task(controller.signal);
      if (!controller.signal.aborted) setStatus(message);
      else if (realm === "official")
        setStatus(
          "Операция отправлена Minecraft Services: отмена не откатывает уже выполненное изменение.",
        );
    } catch (e) {
      if (!controller.signal.aborted) {
        setError(e instanceof Error ? e.message : String(e));
        if (e instanceof TextureServiceError0258 && e.status === 409)
          await refresh().catch(() => undefined);
      }
    } finally {
      if (operation.current === controller) operation.current = null;
      setBusy(false);
      setProgress(null);
    }
  }
  function chooseFile(next: File | null) {
    if (!next) {
      setFile(null);
      return;
    }
    try {
      validateTextureFile0258(next);
      setFile(next);
      setError("");
      setSelected(null);
    } catch (e) {
      setFile(null);
      setError(String(e instanceof Error ? e.message : e));
    }
  }
  const upload = () =>
    void perform(async (signal) => {
      if (!file) throw new Error("Выберите PNG.");
      if (realm === "official") {
        if (!officialClient || !officialProfile)
          throw new Error(
            "Сначала подключите Microsoft-аккаунт в разделе «Вход».",
          );
        if (kind !== "skin")
          throw new Error(
            "Официальные плащи нельзя загружать: выбирайте только принадлежащие аккаунту.",
          );
        onOfficialProfile(
          await officialClient.uploadSkin(
            file,
            model,
            (p) => setProgress(p),
            signal,
          ),
        );
      } else {
        if (!client || !identity)
          throw new Error("Загрузите локальный профиль.");
        await client.upload(
          kind,
          file,
          revision,
          model,
          visibility,
          (p) => setProgress(p),
          signal,
        );
        await refresh(signal);
      }
      setFile(null);
      setSelected(null);
    }, "PNG загружен, назначение обновлено.");
  const select = (item: TextureItem0258) =>
    void perform(async (signal) => {
      if (!client || !identity) throw new Error("Профиль не загружен.");
      await client.select(
        item.kind,
        item.digest,
        revision,
        item.kind === "cape" ? "classic" : model,
        visibility,
      );
      setSelected(null);
      await refresh(signal);
    }, "Текстура выбрана.");
  const reset = () =>
    void perform(async (signal) => {
      if (realm === "official") {
        if (!officialClient || !officialProfile)
          throw new Error("Официальный профиль не подключён.");
        onOfficialProfile(
          kind === "skin"
            ? await officialClient.resetSkin()
            : await officialClient.resetCape(),
        );
      } else {
        if (!client || !assigned || !assigned.active)
          throw new Error("Нет активной текстуры.");
        await client.reset(kind, revision);
        setSelected(null);
        await refresh(signal);
      }
    }, "Текстура сброшена.");
  const deleteSaved = (item: TextureItem0258) => {
    if (
      !window.confirm(
        `Удалить ${item.kind === "skin" ? "скин" : "плащ"} ${item.digest.slice(0, 12)} из библиотеки? ${assigned?.blobDigest === item.digest ? "Текущая текстура будет сброшена." : ""}`,
      )
    )
      return;
    void perform(async (signal) => {
      if (!client) throw new Error("Нет локальной сессии.");
      if (assigned?.active && assigned.blobDigest === item.digest)
        await client.reset(kind, revision, true);
      else await client.deleteSaved(item.kind, item.digest);
      setSelected(null);
      await refresh(signal);
    }, "PNG удалён из личной библиотеки.");
  };
  const change = () =>
    void perform(async (signal) => {
      if (!client || !assigned) throw new Error("Выберите активную текстуру.");
      await client.change(kind, assigned, model, visibility);
      await refresh(signal);
    }, "Настройки текстуры сохранены.");
  const importRemote = () =>
    void perform(async (signal) => {
      if (!client || !identity) throw new Error("Профиль не загружен.");
      const u = new URL(importUrl);
      if (u.protocol !== "https:")
        throw new Error("Импорт допускает только HTTPS URL.");
      await client.importURL(kind, importUrl, revision, model, visibility);
      setImportUrl("");
      setSelected(null);
      await refresh(signal);
    }, "PNG импортирован безопасным серверным загрузчиком.");
  const verifyLocalDelivery = () =>
    void perform(async (signal) => {
      if (!client || !identity || !assigned?.active || !assigned.blobDigest)
        throw new Error("Сначала выберите локальную текстуру.");
      if (assigned.visibility !== "public")
        throw new Error(
          "Для отображения другим игрокам текстура должна быть публичной.",
        );
      await client.verifyYggdrasilDelivery(
        kind,
        identity.profileUuid,
        assigned.blobDigest,
        signal,
      );
    }, "Yggdrasil: подпись, профиль, адрес PNG и SHA-256 подтверждены. Для проверки отображения запустите Minecraft.");
  const selectOfficialCape = (id: string) =>
    void perform(async () => {
      if (!officialClient) throw new Error("Microsoft-профиль не подключён.");
      onOfficialProfile(await officialClient.selectCape(id));
    }, "Выбран принадлежащий официальному аккаунту плащ.");

  return (
    <section className="panel texturesPanel0258">
      <div className="texturesHeader0258">
        <div>
          <h3>Скины и плащи</h3>
          <p>
            Персонализация Minecraft · локальные текстуры Launcher и официальный
            профиль не смешиваются.
          </p>
        </div>
        <button
          type="button"
          disabled={busy || (realm === "local" && !client)}
          onClick={() =>
            void perform(async (signal) => {
              if (realm === "official") {
                if (officialClient && officialProfile)
                  onOfficialProfile(await officialClient.profile());
              } else await refresh(signal);
            }, "Данные обновлены.")
          }
        >
          Обновить
        </button>
      </div>
      <div
        className="textureSwitch0258"
        role="group"
        aria-label="Источник текстур"
      >
        <button
          className={realm === "local" ? "active" : ""}
          onClick={() => setRealm("local")}
          type="button"
        >
          Локальный Launcher
        </button>
        <button
          className={realm === "official" ? "active" : ""}
          onClick={() => setRealm("official")}
          type="button"
        >
          Официальный Minecraft
        </button>
      </div>
      {realm === "local" && !client && (
        <p role="alert">
          Войдите в Launcher в разделе «Вход», чтобы управлять локальными
          текстурами.
        </p>
      )}
      {realm === "local" && client && !identity && (
        <p role="status">Получение текстур локального профиля…</p>
      )}
      {realm === "official" && !officialProfile && (
        <p>
          Подключите официальный Minecraft-аккаунт через Microsoft в разделе
          «Вход». Официальные и локальные UUID/подписи не взаимозаменяемы.
        </p>
      )}
      {((realm === "local" && !!identity) ||
        (realm === "official" && !!officialProfile)) && (
        <>
          <p className="textureProfile0258">
            {realm === "local"
              ? `Локальный профиль: ${identity?.profileName} · ${identity?.profileUuid}`
              : `Microsoft Minecraft: ${officialProfile?.name} · ${officialProfile?.id}`}
          </p>
          <div className="textureContent0258">
            <div>
              <div
                className="textureSwitch0258"
                role="group"
                aria-label="Тип текстуры"
              >
                <button
                  className={kind === "skin" ? "active" : ""}
                  onClick={() => setKind("skin")}
                >
                  Скины
                </button>
                <button
                  className={kind === "cape" ? "active" : ""}
                  onClick={() => setKind("cape")}
                >
                  Плащи
                </button>
              </div>
              {realm === "local" && (
                <>
                  <div className="textureSettings0258">
                    {kind === "skin" && (
                      <label>
                        Модель
                        <select
                          value={model}
                          disabled={busy}
                          onChange={(e) =>
                            setModel(e.target.value as SkinModel0258)
                          }
                        >
                          <option value="classic">Classic (Steve)</option>
                          <option value="slim">Slim (Alex)</option>
                        </select>
                      </label>
                    )}
                    <label>
                      Доступность
                      <select
                        disabled={busy}
                        value={visibility}
                        onChange={(e) =>
                          setVisibility(e.target.value as TextureVisibility0258)
                        }
                      >
                        <option value="public">Публичная</option>
                        <option value="unlisted">По ссылке</option>
                        <option value="private">Приватная</option>
                      </select>
                    </label>
                  </div>
                  <div
                    className="textureUpload0258"
                    onDragOver={(e) => e.preventDefault()}
                    onDrop={(e) => {
                      e.preventDefault();
                      if (!busy) chooseFile(e.dataTransfer.files[0] || null);
                    }}
                  >
                    <label>
                      Загрузить {kind === "skin" ? "скин" : "плащ"} (PNG, до 4
                      МиБ)
                      <input
                        disabled={busy}
                        type="file"
                        accept=".png,image/png"
                        onChange={(e) => {
                          chooseFile(e.target.files?.[0] || null);
                          e.currentTarget.value = "";
                        }}
                      />
                    </label>
                    <small>
                      Перетащите PNG сюда или выберите файл. Геометрия и
                      содержимое проверяются сервером.
                    </small>
                    {file && (
                      <small>
                        {file.name} · {Math.ceil(file.size / 1024)} КиБ
                      </small>
                    )}
                    <button
                      className="primary"
                      disabled={busy || !file}
                      type="button"
                      onClick={upload}
                    >
                      Загрузить и выбрать
                    </button>
                  </div>
                  <details className="textureImport0258">
                    <summary>Импортировать PNG по HTTPS</summary>
                    <label>
                      Ссылка на PNG
                      <input
                        type="url"
                        placeholder="https://example.org/skin.png"
                        value={importUrl}
                        disabled={busy}
                        onChange={(e) => setImportUrl(e.target.value)}
                      />
                    </label>
                    <button
                      disabled={busy || !importUrl.trim()}
                      onClick={importRemote}
                    >
                      Проверить URL и импортировать
                    </button>
                    <small>
                      Запрос выполняется сервером через SSRF-safe fetcher,
                      внешняя ссылка не становится texture URL игрока.
                    </small>
                  </details>
                  <div className="textureActions0258">
                    <button
                      disabled={busy || !assigned?.active}
                      onClick={change}
                    >
                      Сохранить модель / видимость
                    </button>
                    <button
                      type="button"
                      disabled={
                        busy ||
                        !assigned?.active ||
                        !assigned.blobDigest ||
                        assigned.visibility !== "public"
                      }
                      onClick={verifyLocalDelivery}
                    >
                      Проверить доставку Yggdrasil
                    </button>
                    <button
                      className="danger"
                      disabled={busy || !assigned?.active}
                      onClick={reset}
                    >
                      Сбросить {kind === "skin" ? "скин" : "плащ"}
                    </button>
                  </div>
                  {assigned?.active && assigned.visibility !== "public" && (
                    <p role="status">
                      Текстура не опубликована в игровом Yggdrasil: выберите
                      «Публичная» и сохраните настройки для отображения другим
                      игрокам.
                    </p>
                  )}
                  <p className="textureRevision0258">
                    {assigned?.active
                      ? `Активная текстура · ревизия ${revision}`
                      : `Не выбрано · ревизия ${revision}`}
                  </p>
                </>
              )}
              {realm === "official" && (
                <>
                  {kind === "skin" && (
                    <>
                      <label className="textureModel0258">
                        Модель
                        <select
                          disabled={busy}
                          value={model}
                          onChange={(e) =>
                            setModel(e.target.value as SkinModel0258)
                          }
                        >
                          <option value="classic">Classic</option>
                          <option value="slim">Slim</option>
                        </select>
                      </label>
                      <div className="textureUpload0258">
                        <label>
                          Официальный скин PNG
                          <input
                            disabled={busy}
                            type="file"
                            accept=".png,image/png"
                            onChange={(e) => {
                              chooseFile(e.target.files?.[0] || null);
                              e.currentTarget.value = "";
                            }}
                          />
                        </label>
                        <button
                          disabled={busy || !file}
                          className="primary"
                          onClick={upload}
                        >
                          Загрузить в Minecraft Services
                        </button>
                      </div>
                    </>
                  )}
                  {kind === "cape" && (
                    <div className="textureOfficialCapes0258">
                      {officialProfile?.capes.length ? (
                        officialProfile.capes.map((c) => (
                          <button
                            key={c.id}
                            disabled={busy || c.state === "ACTIVE"}
                            className={c.state === "ACTIVE" ? "active" : ""}
                            onClick={() => selectOfficialCape(c.id)}
                          >
                            {c.alias || c.id}
                            {c.state === "ACTIVE" ? " · выбран" : ""}
                          </button>
                        ))
                      ) : (
                        <p>В официальном аккаунте нет доступных плащей.</p>
                      )}
                    </div>
                  )}
                  <div className="textureActions0258">
                    <button
                      className="danger"
                      disabled={busy || (kind === "cape" && !officialCape)}
                      onClick={reset}
                    >
                      {kind === "skin"
                        ? "Сбросить официальный скин"
                        : "Снять официальный плащ"}
                    </button>
                  </div>
                  <small>
                    На Minecraft Services можно выбрать только плащи,
                    принадлежащие этому аккаунту.
                  </small>
                </>
              )}
            </div>
            <div>
              <TexturePreview0258
                skin={skinURL}
                cape={capeURL}
                model={renderModel}
              />
              {progress !== null && (
                <>
                  <div
                    className="textureProgress0258"
                    role="progressbar"
                    aria-label="Загрузка PNG"
                    aria-valuemin={0}
                    aria-valuemax={100}
                    aria-valuenow={progress}
                  >
                    <div style={{ width: `${progress}%` }} />
                  </div>
                  <small role="status">Загрузка PNG: {progress}%</small>
                </>
              )}
              {busy && (
                <button
                  className="textureCancel0258"
                  disabled={realm === "official"}
                  onClick={() => operation.current?.abort()}
                >
                  {realm === "official"
                    ? "Ожидаем подтверждения Minecraft Services…"
                    : "Отменить загрузку / запрос"}
                </button>
              )}
            </div>
          </div>
          {realm === "local" && (
            <>
              <div className="textureLibraryHead0258">
                <h4>Личная библиотека — {shown.length}</h4>
                <small>Выбор не требует повторной загрузки PNG</small>
              </div>
              {shown.length === 0 ? (
                <p>
                  Сохранённых {kind === "skin" ? "скинов" : "плащей"} пока нет.
                </p>
              ) : (
                <>
                  <div className="textureGallery0258">
                    {page.map((item) => (
                      <SavedCard0258
                        key={`${item.kind}-${item.digest}`}
                        item={item}
                        client={client!}
                        busy={busy}
                        active={Boolean(
                          assigned?.active &&
                          assigned.blobDigest === item.digest,
                        )}
                        onChoose={() => select(item)}
                        onDelete={() => deleteSaved(item)}
                        onPreview={() => {
                          setSelected(item);
                          setFile(null);
                          setModel(item.model);
                        }}
                      />
                    ))}
                  </div>
                  <div className="texturePages0258">
                    <button
                      disabled={offset === 0}
                      onClick={() => setOffset(Math.max(0, offset - 12))}
                    >
                      Назад
                    </button>
                    <span>
                      {offset + 1}–{Math.min(offset + 12, shown.length)} из{" "}
                      {shown.length}
                    </span>
                    <button
                      disabled={offset + 12 >= shown.length}
                      onClick={() => setOffset(offset + 12)}
                    >
                      Дальше
                    </button>
                  </div>
                </>
              )}
              <details
                className="textureHistory0258"
                open={showHistory}
                onToggle={(e) => setShowHistory(e.currentTarget.open)}
              >
                <summary>
                  История изменений {kind === "skin" ? "скина" : "плаща"}
                </summary>
                <ul>
                  {history.map((h) => (
                    <li key={`${h.revision}-${h.createdAt}`}>
                      #{h.revision} · {h.event} ·{" "}
                      {new Date(h.createdAt).toLocaleString()}
                    </li>
                  ))}
                </ul>
              </details>
            </>
          )}
        </>
      )}
      {status && (
        <p role="status" className="textureSuccess0258">
          {status}
        </p>
      )}
      {error && (
        <p role="alert" className="textureError0258">
          {error}
        </p>
      )}
    </section>
  );
}
