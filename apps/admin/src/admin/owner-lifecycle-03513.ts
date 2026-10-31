/** Real Admin owner operations: persist a mutation intent before sending it, then
 * independently read its durable job and channel head. Neither HTTP 202 nor a
 * locally cached draft may be reported as a completed publication. */
import type {
  ReleaseApi,
  Preview,
  Operation,
  Draft,
  DraftFields,
} from "../api/release.ts";

export type OwnerKind = "package-publish" | "channel-rollback";
export type OwnerIntent = {
  kind: OwnerKind;
  projectId: string;
  profileId: string;
  channel: string;
  resourceId?: string;
  toVersion?: string;
  idempotencyKey: string;
};
export type ChannelHead = {
  projectId: string;
  profileId: string;
  channel: string;
  revision: number;
  releaseId?: string;
  version?: string;
  manifestDigest?: string;
};
export type OwnerPending = {
  intent: OwnerIntent;
  before: ChannelHead;
  jobId?: string;
};
export type OwnerCheck = {
  phase: "waiting" | "failed" | "staged" | "unconfirmed" | "confirmed";
  message: string;
  job: Operation;
  head?: ChannelHead;
};

const prefix = "launcher.owner-lifecycle.03513";
export function recoveryStorageKey(
  backend: string,
  project: string,
  session: string,
): string {
  return `${prefix}.${encodeURIComponent(backend.replace(/\/$/, ""))}.${encodeURIComponent(session)}.${encodeURIComponent(project)}`;
}
function validIntent(v: unknown): v is OwnerIntent {
  if (!v || typeof v !== "object") return false;
  const x = v as Record<string, unknown>;
  return (
    (x.kind === "package-publish" || x.kind === "channel-rollback") &&
    ["projectId", "profileId", "channel", "idempotencyKey"].every(
      (k) => typeof x[k] === "string" && (x[k] as string).length > 0,
    ) &&
    (x.kind !== "package-publish" ||
      (typeof x.resourceId === "string" && x.resourceId.length > 0)) &&
    (x.kind !== "channel-rollback" ||
      (typeof x.toVersion === "string" && x.toVersion.length > 0)) &&
    (x.idempotencyKey as string).length <= 128
  );
}
function validHead(v: unknown): v is ChannelHead {
  if (!v || typeof v !== "object") return false;
  const x = v as Record<string, unknown>;
  return (
    typeof x.projectId === "string" &&
    typeof x.profileId === "string" &&
    typeof x.channel === "string" &&
    Number.isSafeInteger(x.revision) &&
    (x.revision as number) >= 0 &&
    (x.releaseId === undefined || typeof x.releaseId === "string")
  );
}
export function readOwnerPending(
  storage: Pick<Storage, "getItem">,
  key: string,
  project: string,
): OwnerPending | null {
  try {
    const obj: unknown = JSON.parse(storage.getItem(key) || "null");
    if (!obj || typeof obj !== "object") return null;
    const x = obj as Record<string, unknown>;
    if (
      !validIntent(x.intent) ||
      !validHead(x.before) ||
      x.intent.projectId !== project ||
      x.before.projectId !== x.intent.projectId ||
      x.before.profileId !== x.intent.profileId ||
      x.before.channel !== x.intent.channel ||
      (x.jobId !== undefined && typeof x.jobId !== "string")
    )
      return null;
    return x as OwnerPending;
  } catch {
    return null;
  }
}
export function saveOwnerPending(
  storage: Pick<Storage, "setItem">,
  key: string,
  pending: OwnerPending,
): void {
  if (
    !validIntent(pending.intent) ||
    !validHead(pending.before) ||
    pending.before.projectId !== pending.intent.projectId ||
    pending.before.profileId !== pending.intent.profileId ||
    pending.before.channel !== pending.intent.channel
  )
    throw Error("Недопустимый owner intent");
  storage.setItem(key, JSON.stringify(pending));
}
export function clearOwnerPending(
  storage: Pick<Storage, "removeItem">,
  key: string,
): void {
  storage.removeItem(key);
}

export async function prepareOwnerOperation(
  api: ReleaseApi,
  intent: OwnerIntent,
): Promise<{ before: ChannelHead; preview: Preview }> {
  if (!validIntent(intent)) throw Error("Некорректная операция");
  const before = await api.channelHead(
    intent.projectId,
    intent.profileId,
    intent.channel,
  );
  if (
    !validHead(before) ||
    before.projectId !== intent.projectId ||
    before.profileId !== intent.profileId ||
    before.channel !== intent.channel
  )
    throw Error("Backend вернул некорректную привязку канала");
  const preview = await api.validateOperation(intent);
  if (!preview.valid) throw Error("Backend отклонил операцию");
  return { before, preview };
}

export async function observeOwnerOperation(
  api: ReleaseApi,
  pending: OwnerPending,
): Promise<OwnerCheck> {
  const job = await api.operation(pending.jobId || "");
  if (
    job.projectId !== pending.intent.projectId ||
    job.kind !== pending.intent.kind ||
    job.resourceId !==
      (pending.intent.kind === "package-publish"
        ? pending.intent.resourceId
        : pending.intent.channel) ||
    (pending.jobId && job.id !== pending.jobId)
  )
    throw Error("Job не соответствует выбранной операции/проекту");
  if (["failed", "dead", "revoked", "cancelled"].includes(job.status)) {
    return {
      phase: "failed",
      job,
      message: `Job ${job.id}: ${job.status}. Проверьте причину и журнал перед повтором.`,
    };
  }
  if (job.status !== "succeeded")
    return {
      phase: "waiting",
      job,
      message: `Job ${job.id}: ${job.status}. Ожидается подтверждение Backend.`,
    };
  if (
    pending.intent.kind === "channel-rollback" &&
    job.result?.status === "rollback-staged-runtime-validation-required"
  ) {
    return {
      phase: "staged",
      job,
      message: `Откат подготовлен как новый пакет ${String(job.result.packageId || "")}, но канал НЕ переключён. Выполните требуемую runtime-сертификацию этого пакета и опубликуйте его штатным workflow.`,
    };
  }
  const head = await api.channelHead(
    pending.intent.projectId,
    pending.intent.profileId,
    pending.intent.channel,
  );
  if (
    !validHead(head) ||
    head.projectId !== pending.intent.projectId ||
    head.profileId !== pending.intent.profileId ||
    head.channel !== pending.intent.channel
  )
    throw Error("Невозможно подтвердить состояние канала");
  // A succeeded job is insufficient evidence if another release has since
  // advanced the channel, or the job response belongs to a different package.
  const committedRevision = head.revision === pending.before.revision + 1;
  const matches =
    pending.intent.kind === "package-publish"
      ? committedRevision &&
        job.result?.status === "published" &&
        job.result?.releaseId === pending.intent.resourceId &&
        head.releaseId === pending.intent.resourceId
      : committedRevision &&
        job.result?.status ===
          "rolled-back-as-new-validated-immutable-release" &&
        typeof job.result?.packageId === "string" &&
        head.releaseId === job.result.packageId; // Rollback creates a NEW release.
  return {
    phase: matches ? "confirmed" : "unconfirmed",
    job,
    head,
    message: matches
      ? `Канал ${head.channel} подтверждён: ревизия ${head.revision}, релиз ${head.version || head.releaseId}.`
      : "Job завершился, но текущий channel head не подтверждает ожидаемый результат. Проверьте аудит и параллельные операции.",
  };
}

/** Continue a stable rollback that was deliberately staged by the Backend.
 * No manual package URL or SQL edits; server validates this fresh owner draft. */
export async function openStagedRollback(
  api: ReleaseApi,
  pending: OwnerPending,
  check: OwnerCheck,
): Promise<{ draft: Draft; fields: DraftFields }> {
  if (
    pending.intent.kind !== "channel-rollback" ||
    check.phase !== "staged" ||
    check.job.id !== pending.jobId
  )
    throw Error("Нет подтверждённого подготовленного rollback");
  const packageId = check.job.result?.packageId;
  if (typeof packageId !== "string" || !packageId)
    throw Error("Backend не вернул ID подготовленного пакета");
  const pkg = await api.package(packageId);
  if (
    pkg.packageId !== packageId ||
    pkg.projectId !== pending.intent.projectId ||
    pkg.profileId !== pending.intent.profileId ||
    pkg.channel !== pending.intent.channel ||
    pkg.status === "published" ||
    !pkg.version ||
    !pkg.minecraft?.version ||
    !pkg.minecraft.loader
  )
    throw Error(
      "Подготовленный rollback не соответствует доверенному проекту, профилю или каналу",
    );
  const fields: DraftFields = {
    projectId: pkg.projectId,
    profileId: pkg.profileId,
    channel: pkg.channel,
    version: pkg.version,
    minecraftVersion: pkg.minecraft.version,
    loader: pkg.minecraft.loader,
    packageId,
    jobId: "",
    step: "verify",
  };
  return { draft: await api.create(fields), fields };
}
