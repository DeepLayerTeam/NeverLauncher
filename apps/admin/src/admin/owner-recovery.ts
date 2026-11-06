import type { ReleaseApi, Operation } from "../api/release.ts";
import type { OwnerPending } from "./owner-lifecycle-03513.ts";

/** Учётные данные здесь не записываются. Область определяется проверенным пользователем
 * после входа, а не временным ID сеанса; аутентификация и права остаются в API. */
export function durableOwnerKey(
  backend: string,
  userId: string,
  projectId: string,
  workflow: "release" | "operations" | "bridge" = "release",
): string {
  if (!backend.trim() || !userId.trim() || !projectId.trim())
    throw Error("Требуется авторизация владельца");
  return `launcher.owner.0388.${workflow}.${encodeURIComponent(backend.replace(/\/$/, ""))}.${encodeURIComponent(userId)}.${encodeURIComponent(projectId)}`;
}
export async function findOriginalOwnerJob(
  api: ReleaseApi,
  pending: OwnerPending,
): Promise<Operation | null> {
  let job: Operation;
  try {
    job = await api.recoverOperation(
      pending.intent.projectId,
      pending.intent.kind,
      pending.intent.idempotencyKey,
    );
  } catch (err) {
    if (
      typeof err === "object" &&
      err !== null &&
      "status" in err &&
      err.status === 404
    )
      return null;
    throw err;
  }
  const resource =
    pending.intent.kind === "package-publish"
      ? pending.intent.resourceId
      : pending.intent.channel;
  if (
    !job.id ||
    job.projectId !== pending.intent.projectId ||
    job.kind !== pending.intent.kind ||
    job.resourceId !== resource
  )
    throw Error("Серверный журнал не соответствует сохранённой операции");
  if (pending.jobId && pending.jobId !== job.id)
    throw Error("Журнал операций вернул другую задачу");
  return job;
}
