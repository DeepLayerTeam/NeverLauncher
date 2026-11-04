import type { ReleaseApi, Operation } from "../api/release.ts";
import type { OwnerPending } from "./owner-lifecycle-03513.ts";

/** No credentials are written here. Scope by verified logged-in actor,
 * by the transient session ID; authentication/permissions still live on API. */
export function durableOwnerKey(
  backend: string,
  userId: string,
  projectId: string,
  workflow: "release" | "operations" | "bridge" = "release",
): string {
  if (!backend.trim() || !userId.trim() || !projectId.trim())
    throw Error("Authenticated owner scope required");
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
    throw Error("Backend journal does not match the saved operation");
  if (pending.jobId && pending.jobId !== job.id)
    throw Error("Operation journal returned a different job");
  return job;
}
