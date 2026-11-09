import { statusRu } from "./status-ru";
import React, { useCallback, useEffect, useState } from "react";
import { requestJSON } from "../api/client";

type Run = {
  id: string;
  projectId: string;
  status: "pending" | "running" | "failed" | "paused" | "prepared";
  step: string;
  revision: number;
  fence: number;
  lastError?: string;
  result: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
};
type Finding0332 = {
  code: string;
  severity: string;
  component: string;
  path?: string;
  message: string;
};
type Compatibility0332 = {
  sourceSha256: string;
  sourceEntries: number;
  sourceBytes?: number;
  sourceTotalBytes?: number;
  filesSha256?: string;
  serverJarSha256?: string;
  categories?: Record<string, number>;
  claimedVersion?: string;
  detectedVersion?: string;
  versionStatus: string;
  versionEvidence: string;
  status: string;
  cutoverAllowed: boolean;
  components: { kind: string; path: string; status: string; type?: string }[];
  findings: Finding0332[];
  summary: Record<string, number>;
};
type Inventory0333 = {
  format: string;
  sourceSha256: string;
  sourceEntries: number;
  sourceBytes: number;
  totalBytes: number;
  sensitiveEntries: number;
  manifestSha256: string;
  categories: Record<string, number>;
  authProviders: Record<string, number>;
  textureProviders: Record<string, number>;
  optionalActions: Record<string, number>;
  serverReferences: number;
  files: {
    path: string;
    kind: string;
    size: number;
    sha256: string;
    sensitive?: boolean;
  }[];
};
type Identity0334 = {
  format: string;
  runId: string;
  sourceSha256: string;
  inventorySha256: string;
  entriesSha256: string;
  summary: Record<string, number>;
  ready: boolean;
  rows: {
    provider: string;
    sourceId: string;
    username: string;
    uuid: string;
    sourcePath: string;
    targetUserId?: string;
    status: string;
    reason: string;
  }[];
};
type Credentials0335 = {
  format: string;
  runId: string;
  sourceSha256: string;
  identitySha256: string;
  imported: number;
  existingUnchanged: number;
  manualReset: number;
  complete: boolean;
  dryRun: boolean;
  rows: {
    provider: string;
    sourceId: string;
    username: string;
    uuid: string;
    state: string;
    reason?: string;
  }[];
};
type Security0336 = {
  format: string;
  runId: string;
  importedAccounts: number;
  existingNeverUntouched: number;
  manualResets: number;
  sessionsRevoked: number;
  devicesRevoked: number;
  challengesConsumed: number;
  hardwareEvidenceDeleted: number;
  measuredBootEvidenceDeleted: number;
  activeJwtKid: string;
  manifestPublicSha256: string;
  appliedAt?: string;
  verified: boolean;
  readyForCutover: boolean;
  requiresLogin: boolean;
  requiresDeviceEnrollment: boolean;
  requiresGuardAttestation: boolean;
};
type ContentPlan0337 = {
  format: string;
  sourceSha256: string;
  inventorySha256: string;
  profilePath: string;
  sourceDirectory?: string;
  skippedFiles?: { sourcePath: string; reason: string }[];
  filesSha256: string;
  ready: boolean;
  blockers: string[];
  files: {
    sourcePath: string;
    targetPath: string;
    size: number;
    sha256: string;
    ownership: string;
  }[];
  profile: {
    fields: { field: string; status: string; reason: string }[];
    settings: unknown;
  };
  optional?: {
    ready: boolean;
    summary: Record<string, number>;
    fields: { field: string; status: string; reason: string }[];
  };
};
type MigrationPlan0442 = {
  format: string;
  runId: string;
  projectId: string;
  sourceSha256: string;
  inventorySha256: string;
  targetSha256: string;
  planSha256: string;
  targetUnchanged?: boolean;
  status: "manual" | "blocked";
  destination: {
    profilePath: string;
    profileId: string;
    profileName: string;
    loader: string;
    channel: string;
    version: string;
  };
  counts: Record<string, number>;
  transferBytes: number;
  blockers: string[];
  checklist: { action: string; detail: string; required: boolean }[];
  items: { source: string; target?: string; kind: string; status: string; bytes: number; reason?: string }[];
  content: ContentPlan0337;
  identities: { sourceAccounts: number; duplicateOrConflicting: number; state: string; reason?: string };
};
type ContentState0337 = {
  plan: ContentPlan0337;
  workspaceId: string;
  workspaceRevision: number;
  state: string;
  stagedFiles: number;
  totalFiles: number;
  complete: boolean;
  validation: string;
  buildWorkspaceUrl: string;
};
type Modules0338 = {
  format: string;
  sourceSha256: string;
  inventorySha256: string;
  ready: boolean;
  cutoverAllowed: boolean;
  blockers: string[];
  modules: {
    path: string;
    sha256: string;
    name: string;
    implementation: string;
    status: string;
    reason: string;
    authHook: boolean;
    launchHook: boolean;
    sourcesPresent: boolean;
  }[];
  wrappers: {
    path: string;
    mode: string;
    serverName?: string;
    legacyTokenPresent: boolean;
    legacyAddressPresent: boolean;
    replacement: string;
    status: string;
    reason: string;
  }[];
};
type BridgeStatus0446 = {
  serverId: string;
  wrapperPath: string;
  projectId: string;
  profileId: string;
  state: "online" | "awaiting_runtime" | "awaiting_registration" | "blocked";
  reason: string;
  cutoverAllowed: boolean;
};
type Rehearsal03310 = {
  liveSession?: { clientSha256: string; playerName: string; playerUuid: string; startedAt: string; joinedAt: string };
  format: string;
  runId: string;
  stageId: string;
  sourceInventorySha256: string;
  sourceSnapshotSha256: string;
  targetSnapshotSha256: string;
  ready: boolean;
  cutoverAllowed: boolean;
  blockers: string[];
  probes: {
    name: string;
    passed: boolean;
    uuid?: string;
    evidenceSha256: string;
  }[];
};
type Cutover03311 = {
  runId: string;
  projectId: string;
  profileId: string;
  channel: string;
  stageId: string;
  releaseId: string;
  releaseVersion: string;
  targetDigest: string;
  baselineRevision: number;
  baselineReleaseId: string;
  baselineVersion: string;
  state: "staged" | "active" | "cancelled" | "rolled_back";
  revision: number;
  activatedRevision?: number;
  fenceReference?: string;
  fenceEvidenceSha256?: string;
};
type Rollback03312 = {
  format: string;
  runId: string;
  profileId: string;
  channel: string;
  state: string;
  routeRevision: number;
  planSha256: string;
  ready: boolean;
  blockers: string[];
  currentSnapshotSha256: string;
  mode: string;
  reconciledSourceSha256?: string;
};
type MigrationReport03313 = {
  format: string;
  runId: string;
  projectId: string;
  status: string;
  reportSha256: string;
  counts: Record<string, number>;
  blockers: string[];
  evidence: {
    stage: string;
    state: string;
    sha256?: string;
    details?: string;
  }[];
  items: {
    kind: string;
    source: string;
    target?: string;
    status: string;
    sha256?: string;
    reason?: string;
  }[];
  identities: {
    provider: string;
    sourceId: string;
    username: string;
    uuid: string;
    targetUserId: string;
    status: string;
  }[];
  operatorDecisions: { sequence: number; kind: string; revision: number }[];
};
type ReportReview03313 = {
  status: string;
  reviewedBy: string;
  reviewedAt: string;
  evidenceSHA256?: string;
  evidenceSha256: string;
  report: MigrationReport03313;
};
type Event = {
  sequence: number;
  kind: string;
  step: string;
  revision: number;
  detail: unknown;
  createdAt: string;
};

/** Рабочий оператор миграций, состояние которых хранится на сервере. Клиентское состояние не
 * является авторитетным. Все изменения защищены fencing и фиксируются в Backend. */
export function MigrationCenter0331({
  backendUrl,
  token,
  projectId,
}: {
  backendUrl: string;
  token: string;
  projectId: string;
}) {
  const [key, setKey] = useState("");
  const [runs, setRuns] = useState<Run[]>([]);
  const [runId, setRunId] = useState("");
  const [run, setRun] = useState<Run | null>(null);
  const [events, setEvents] = useState<Event[]>([]);
  const [report03313, setReport03313] = useState<MigrationReport03313 | null>(
    null,
  );
  const [review03313, setReview03313] = useState<ReportReview03313 | null>(
    null,
  );
  const [reportRef03313, setReportRef03313] = useState("");
  const [reportEvidence03313, setReportEvidence03313] = useState("");
  const [reportConfirm03313, setReportConfirm03313] = useState("");
  const [busy, setBusy] = useState(false);
  const [source, setSource] = useState<File | null>(null);
  const [claimedVersion, setClaimedVersion] = useState("");
  const [compatibility, setCompatibility] = useState<Compatibility0332 | null>(
    null,
  );
  const [inventory, setInventory] = useState<Inventory0333 | null>(null);
  const [identities, setIdentities] = useState<Identity0334 | null>(null);
  const [credentials, setCredentials] = useState<Credentials0335 | null>(null);
  const [credentialPreview, setCredentialPreview] =
    useState<Credentials0335 | null>(null);
  const [security, setSecurity] = useState<Security0336 | null>(null);
  const [securityPreview, setSecurityPreview] = useState<Security0336 | null>(
    null,
  );
  const [freshKeysConfirmed, setFreshKeysConfirmed] = useState(false);
  const [securityRunConfirm, setSecurityRunConfirm] = useState("");
  const [contentProfilePath, setContentProfilePath] = useState(
    "profiles/client.json",
  );
  const [contentProfileId, setContentProfileId] = useState("gravit-client");
  const [contentProfileName, setContentProfileName] = useState("");
  const [contentLoader, setContentLoader] = useState("vanilla");
  const [contentVersion, setContentVersion] = useState("migrated-1");
  const [contentChannel, setContentChannel] = useState("stable");
  const [contentConfirm, setContentConfirm] = useState("");
  const [migrationPlan0442, setMigrationPlan0442] = useState<MigrationPlan0442 | null>(null);
  const [contentPreview, setContentPreview] = useState<ContentPlan0337 | null>(
    null,
  );
  const [contentState, setContentState] = useState<ContentState0337 | null>(
    null,
  );
  const [modules0338, setModules0338] = useState<Modules0338 | null>(null);
  const [bridgeStatus0446, setBridgeStatus0446] = useState<BridgeStatus0446 | null>(null);
  const [rehearsal03310, setRehearsal03310] = useState<Rehearsal03310 | null>(
    null,
  );
  const [cutovers03311, setCutovers03311] = useState<Cutover03311[]>([]);
  const [rollbackSnapshot03312, setRollbackSnapshot03312] = useState("");
  const [rollbackSourceSnapshot03312, setRollbackSourceSnapshot03312] =
    useState("");
  const [rollbackReconcileHash03312, setRollbackReconcileHash03312] =
    useState("");
  const [rollbackRef03312, setRollbackRef03312] = useState("");
  const [rollbackHash03312, setRollbackHash03312] = useState("");
  const [rollbackNeverFenced03312, setRollbackNeverFenced03312] =
    useState(false);
  const [rollbackSourceFenced03312, setRollbackSourceFenced03312] =
    useState(false);
  const [rollbackPlan03312, setRollbackPlan03312] =
    useState<Rollback03312 | null>(null);
  const [cutoverProfile03311, setCutoverProfile03311] = useState("");
  const [cutoverChannel03311, setCutoverChannel03311] = useState("stable");
  const [cutoverRelease03311, setCutoverRelease03311] = useState("");
  const [cutoverHeadRev03311, setCutoverHeadRev03311] = useState("0");
  const [cutoverConfirm03311, setCutoverConfirm03311] = useState("");
  const [cutoverFenceRef03311, setCutoverFenceRef03311] = useState("");
  const [cutoverFenceSha03311, setCutoverFenceSha03311] = useState("");
  const [cutoverSnapshot03311, setCutoverSnapshot03311] = useState("");
  const [cutoverReceipt0448, setCutoverReceipt0448] = useState("");
  const [cutoverSourceStopped03311, setCutoverSourceStopped03311] =
    useState(false);
  const [wrapperPath0338, setWrapperPath0338] = useState("");
  const [bridgeNode0338, setBridgeNode0338] = useState("");
  const [bridgeName0338, setBridgeName0338] = useState("");
  const [bridgeKind0338, setBridgeKind0338] = useState("paper");
  const [bridgeProfile0338, setBridgeProfile0338] = useState("");
  const [bridgePublicKey0338, setBridgePublicKey0338] = useState("");
  const [bridgeConfirm0338, setBridgeConfirm0338] = useState("");
  const [bridgeFreshKeys0338, setBridgeFreshKeys0338] = useState(false);
  const [passwordFormat, setPasswordFormat] = useState("");
  const [confirmRun, setConfirmRun] = useState("");
  const [error, setError] = useState("");
  const base = "/api/v1/admin/migration-runs";

  const refresh = useCallback(
    async (selectedId = runId) => {
      if (!projectId) return;
      const all = await requestJSON<Run[]>(
        backendUrl,
        `${base}?projectId=${encodeURIComponent(projectId)}`,
        token,
      );
      setRuns(all);
      if (!selectedId) {
        setRun(null);
        setEvents([]);
        setCompatibility(null);
        setInventory(null);
        setIdentities(null);
        setCredentials(null);
        return;
      }
      const [current, journal] = await Promise.all([
        requestJSON<Run>(
          backendUrl,
          `${base}/${encodeURIComponent(selectedId)}`,
          token,
        ),
        requestJSON<Event[]>(
          backendUrl,
          `${base}/${encodeURIComponent(selectedId)}/events`,
          token,
        ),
      ]);
      setRun(current);
      try {
        setMigrationPlan0442(await requestJSON<MigrationPlan0442>(backendUrl, `${base}/${encodeURIComponent(selectedId)}/dry-run`, token));
      } catch (e) {
        if (e instanceof Error && "status" in e && (e as { status?: number }).status === 404)
          setMigrationPlan0442(null);
        else throw e;
      }
      setEvents(journal);
      setReport03313(null);
      setReview03313(null);
      setCutovers03311(
        await requestJSON<Cutover03311[]>(
          backendUrl,
          `${base}/${encodeURIComponent(selectedId)}/cutovers`,
          token,
        ),
      );
      try {
        setInventory(
          await requestJSON<Inventory0333>(
            backendUrl,
            `${base}/${encodeURIComponent(selectedId)}/inventory`,
            token,
          ),
        );
      } catch (e) {
        if (
          e instanceof Error &&
          "status" in e &&
          (e as { status?: number }).status === 404
        )
          setInventory(null);
        else throw e;
      }
      try {
        setIdentities(
          await requestJSON<Identity0334>(
            backendUrl,
            `${base}/${encodeURIComponent(selectedId)}/identities`,
            token,
          ),
        );
      } catch (e) {
        if (
          e instanceof Error &&
          "status" in e &&
          (e as { status?: number }).status === 404
        )
          setIdentities(null);
        else throw e;
      }
      try {
        setCredentials(
          await requestJSON<Credentials0335>(
            backendUrl,
            `${base}/${encodeURIComponent(selectedId)}/credentials`,
            token,
          ),
        );
      } catch (e) {
        if (
          e instanceof Error &&
          "status" in e &&
          (e as { status?: number }).status === 404
        )
          setCredentials(null);
        else throw e;
      }
      try {
        setRehearsal03310(
          await requestJSON<Rehearsal03310>(
            backendUrl,
            `${base}/${encodeURIComponent(selectedId)}/rehearsal`,
            token,
          ),
        );
      } catch (e) {
        if (
          e instanceof Error &&
          "status" in e &&
          (e as { status?: number }).status === 404
        )
          setRehearsal03310(null);
        else throw e;
      }
      try {
        setModules0338(
          await requestJSON<Modules0338>(
            backendUrl,
            `${base}/${encodeURIComponent(selectedId)}/modules`,
            token,
          ),
        );
      } catch (e) {
        if (
          e instanceof Error &&
          "status" in e &&
          (e as { status?: number }).status === 404
        )
          setModules0338(null);
        else throw e;
      }
      try {
        setCompatibility(
          await requestJSON<Compatibility0332>(
            backendUrl,
            `${base}/${encodeURIComponent(selectedId)}/compatibility`,
            token,
          ),
        );
      } catch (e) {
        if (
          e instanceof Error &&
          "status" in e &&
          (e as { status?: number }).status === 404
        )
          setCompatibility(null);
        else throw e;
      }
    },
    [backendUrl, token, projectId, runId],
  );

  useEffect(() => {
    setRunId("");
    setRun(null);
    setEvents([]);
    setRuns([]);
    setCompatibility(null);
    setInventory(null);
    setIdentities(null);
    setCredentials(null);
    setCredentialPreview(null);
    setMigrationPlan0442(null);
    setCutovers03311([]);
    setConfirmRun("");
    setError("");
    if (projectId)
      void requestJSON<Run[]>(
        backendUrl,
        `${base}?projectId=${encodeURIComponent(projectId)}`,
        token,
      )
        .then(setRuns)
        .catch((e: Error) => setError(e.message));
  }, [backendUrl, token, projectId]);

  async function reportAction03313(action: "generate" | "review" | "status") {
    if (!runId || busy) return;
    setBusy(true);
    setError("");
    const path = `${base}/${encodeURIComponent(runId)}/report`;
    try {
      if (action === "generate")
        setReport03313(
          await requestJSON<MigrationReport03313>(backendUrl, path, token),
        );
      if (action === "status")
        setReview03313(
          await requestJSON<ReportReview03313>(
            backendUrl,
            path + "/review",
            token,
          ),
        );
      if (action === "review") {
        if (
          reportConfirm03313 !== runId ||
          !report03313 ||
          report03313.blockers.length ||
          report03313.status !== "review_required"
        )
          return;
        const reviewed = await requestJSON<ReportReview03313>(
          backendUrl,
          path + "/review",
          token,
          {
            method: "POST",
            headers: { "X-Migration-RC-Confirm": runId },
            body: JSON.stringify({
              reportSha256: report03313.reportSha256,
              evidenceSha256: reportEvidence03313,
              evidenceReference: reportRef03313,
            }),
          },
        );
        setReview03313(reviewed);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  function downloadReport03313() {
    if (!report03313) return;
    const blob = new Blob([JSON.stringify(report03313, null, 2) + "\n"], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `migration-report-${runId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }
  async function cutoverAction03311(
    action: "stage" | "activate" | "cancel",
    route?: Cutover03311,
  ) {
    if (!runId || busy || cutoverConfirm03311 !== runId) return;
    const scope = route ?? {
      profileId: cutoverProfile03311,
      channel: cutoverChannel03311,
    };
    let body: Record<string, unknown> = {
      profileId: scope.profileId,
      channel: scope.channel,
    };
    if (action === "stage") {
      const rev = Number(cutoverHeadRev03311);
      if (!Number.isSafeInteger(rev) || rev < 0 || !rehearsal03310?.ready)
        return;
      body = {
        ...body,
        releaseId: cutoverRelease03311,
        expectedHeadRevision: rev,
        stageId: rehearsal03310.stageId,
      };
    } else if (route) {
      body = { ...body, expectedRevision: route.revision };
      if (action === "activate") {
        if (!cutoverSourceStopped03311) return;
        let receipt: unknown;
        try {
          receipt = JSON.parse(cutoverReceipt0448);
        } catch {
          setError("Нужен JSON оригинального подтверждения блокировки записи в источнике, полученной после остановки службы");
          return;
        }
        body = {
          ...body,
          sourceFenceReference: cutoverFenceRef03311,
          sourceFenceEvidenceSha256: cutoverFenceSha03311,
          currentSourceSnapshotSha256: cutoverSnapshot03311,
          sourceFenceReceipt: receipt,
        };
      }
    } else return;
    setBusy(true);
    setError("");
    try {
      await requestJSON(
        backendUrl,
        `${base}/${encodeURIComponent(runId)}/cutovers/${action}`,
        token,
        {
          method: "POST",
          headers: {
            "X-Migration-Cutover-Confirm": runId,
            ...(action === "activate"
              ? { "X-Migration-Source-Fenced": "true" }
              : {}),
          },
          body: JSON.stringify(body),
        },
      );
      await refresh(runId);
    } catch (e) {
      setError(String(e));
      await refresh(runId).catch(() => undefined);
    } finally {
      setBusy(false);
    }
  }

  async function rollbackAction03312(
    action: "plan" | "commit",
    route: Cutover03311,
  ) {
    if (
      !runId ||
      busy ||
      cutoverConfirm03311 !== runId ||
      !rollbackNeverFenced03312 ||
      route.state !== "active"
    )
      return;
    if (
      action === "commit" &&
      (!rollbackSourceFenced03312 ||
        !rollbackPlan03312?.ready ||
        rollbackPlan03312.routeRevision !== route.revision)
    )
      return;
    let current: unknown;
    try {
      current = JSON.parse(rollbackSnapshot03312);
    } catch {
      setError(
        "Введите JSON актуального снимка состояния отдельно остановленного Never или игрового сервера",
      );
      return;
    }
    let body: Record<string, unknown> = {
      profileId: route.profileId,
      channel: route.channel,
      expectedRevision: route.revision,
      current,
    };
    if (rollbackSourceSnapshot03312.trim()) {
      try {
        body = {
          ...body,
          reconciledSource: JSON.parse(rollbackSourceSnapshot03312),
          reconciliationEvidenceSha256: rollbackReconcileHash03312,
        };
      } catch {
        setError("Некорректный JSON согласованного снимка Gravit");
        return;
      }
    }
    if (action === "plan")
      body = {
        ...body,
        evidenceReference: rollbackRef03312,
        evidenceSha256: rollbackHash03312,
      };
    else
      body = {
        ...body,
        planSha256: rollbackPlan03312?.planSha256,
        sourceWriterFenced: true,
        WriterFenced: true,
        currentEvidenceSha256: rollbackHash03312,
      };
    setBusy(true);
    setError("");
    try {
      const result = await requestJSON<Rollback03312>(
        backendUrl,
        `${base}/${encodeURIComponent(runId)}/rollbacks/${action}`,
        token,
        {
          method: "POST",
          headers: {
            "X-Migration-Rollback-Confirm": runId,
            "X-Writer-Fenced": "true",
            ...(action === "commit"
              ? { "X-Migration-Source-Fenced": "true" }
              : {}),
          },
          body: JSON.stringify(body),
        },
      );
      setRollbackPlan03312(result);
      await refresh(runId);
    } catch (e) {
      setError(String(e));
      await refresh(runId).catch(() => undefined);
    } finally {
      setBusy(false);
    }
  }

  async function create(event: React.FormEvent) {
    event.preventDefault();
    if (!projectId || key.length < 8 || busy) return;
    setBusy(true);
    setError("");
    try {
      const saved = await requestJSON<Run>(backendUrl, base, token, {
        method: "POST",
        body: JSON.stringify({
          projectId,
          sourceKind: "gravit",
          idempotencyKey: key,
        }),
      });
      setRunId(saved.id);
      await refresh(saved.id);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
    // После сетевой ошибки с неопределённым исходом сохраняйте ключ идемпотентности для безопасного повтора.
  }
  async function operate(action: "execute" | "pause" | "resume") {
    if (!runId || busy) return;
    setBusy(true);
    setError("");
    try {
      await requestJSON<Run>(
        backendUrl,
        `${base}/${encodeURIComponent(runId)}/${action}`,
        token,
        { method: "POST", body: "{}" },
      );
      await refresh(runId);
    } catch (e) {
      // При ошибочном или неопределённом ответе перечитайте сохранённое состояние перед повторной отправкой.
      setError(String(e));
      await refresh(runId).catch(() => undefined);
    } finally {
      setBusy(false);
    }
  }
  async function assess(event: React.FormEvent) {
    event.preventDefault();
    if (!runId || !source || busy) return;
    if (source.size < 1 || source.size > 512 * 1024 * 1024) {
      setError("Размер ZIP должен быть от 1 до 512 МиБ");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const result = await requestJSON<Compatibility0332>(
        backendUrl,
        `${base}/${encodeURIComponent(runId)}/compatibility`,
        token,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/zip",
            "X-Gravit-Version": claimedVersion,
          },
          body: source,
        },
      );
      setCompatibility(result);
      await refresh(runId);
    } catch (e) {
      setError(String(e));
      await refresh(runId).catch(() => undefined);
    } finally {
      setBusy(false);
    }
  }
  async function inventorySource() {
    if (!runId || !source || busy) return;
    if (source.size < 1 || source.size > 512 * 1024 * 1024) {
      setError("Размер ZIP должен быть от 1 до 512 МиБ");
      return;
    }
    setBusy(true);
    setError("");
    try {
      await requestJSON<Inventory0333>(
        backendUrl,
        `${base}/${encodeURIComponent(runId)}/inventory`,
        token,
        {
          method: "POST",
          headers: { "Content-Type": "application/zip" },
          body: source,
        },
      );
      await refresh(runId);
    } catch (e) {
      setError(String(e));
      await refresh(runId).catch(() => undefined);
    } finally {
      setBusy(false);
    }
  }
  async function mapIdentities() {
    if (!runId || !source || !inventory || busy) return;
    setBusy(true);
    setError("");
    try {
      const result = await requestJSON<Identity0334>(
        backendUrl,
        `${base}/${encodeURIComponent(runId)}/identities`,
        token,
        {
          method: "POST",
          headers: { "Content-Type": "application/zip" },
          body: source,
        },
      );
      setIdentities(result);
      await refresh(runId);
    } catch (e) {
      setError(String(e));
      await refresh(runId).catch(() => undefined);
    } finally {
      setBusy(false);
    }
  }
  async function verifyIdentities() {
    if (!runId || busy || !identities) return;
    setBusy(true);
    setError("");
    try {
      await requestJSON<Identity0334>(
        backendUrl,
        `${base}/${encodeURIComponent(runId)}/identities/verify`,
        token,
        { method: "POST", body: "{}" },
      );
      await refresh(runId);
    } catch (e) {
      setError(String(e));
      await refresh(runId).catch(() => undefined);
    } finally {
      setBusy(false);
    }
  }
  async function migrationCredentials(commit: boolean) {
    if (!runId || !source || !identities || !inventory || busy) return;
    if (commit && (confirmRun !== runId || !credentialPreview)) {
      setError(
        "Для импорта введите точный ID запуска и выполните предварительную проверку",
      );
      return;
    }
    setBusy(true);
    setError("");
    try {
      const action = commit ? "import" : "preview";
      const report = await requestJSON<Credentials0335>(
        backendUrl,
        `${base}/${encodeURIComponent(runId)}/credentials/${action}`,
        token,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/zip",
            "X-Gravit-Password-Format": passwordFormat,
            ...(commit ? { "X-Migration-Import-Confirm": runId } : {}),
          },
          body: source,
        },
      );
      if (commit) {
        setCredentials(report);
        setCredentialPreview(null);
        setConfirmRun("");
        await refresh(runId);
      } else setCredentialPreview(report);
    } catch (e) {
      setError(String(e));
      await refresh(runId).catch(() => undefined);
    } finally {
      setBusy(false);
    }
  }
  async function migrationSecurity0336(activate: boolean) {
    if (!runId || busy || !credentials) return;
    if (
      activate &&
      (!securityPreview || securityRunConfirm !== runId || !freshKeysConfirmed)
    ) {
      setError(
        "Для смены доверия сначала выполните предварительный просмотр, проверьте ключи и введите точный идентификатор запуска",
      );
      return;
    }
    setBusy(true);
    setError("");
    try {
      const result = await requestJSON<Security0336>(
        backendUrl,
        `${base}/${encodeURIComponent(runId)}/security/${activate ? "activate" : "preview"}`,
        token,
        {
          method: "POST",
          headers: activate
            ? {
                "X-Migration-Trust-Confirm": runId,
                "X-Migration-Fresh-Keys-Confirmed": "true",
              }
            : undefined,
        },
      );
      if (activate) {
        setSecurity(result);
        setSecurityPreview(null);
        setSecurityRunConfirm("");
        setFreshKeysConfirmed(false);
        await refresh(runId);
      } else setSecurityPreview(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  async function verifySecurity0336() {
    if (!runId || busy) return;
    setBusy(true);
    setError("");
    try {
      const result = await requestJSON<Security0336>(
        backendUrl,
        `${base}/${encodeURIComponent(runId)}/security`,
        token,
      );
      setSecurity(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  async function migrationDryRun0442() {
    if (!runId || !source || !inventory || !compatibility || busy) return;
    setBusy(true);
    setError("");
    try {
      const result = await requestJSON<MigrationPlan0442>(
        backendUrl,
        `${base}/${encodeURIComponent(runId)}/dry-run`,
        token,
        { method: "POST", headers: {
          "Content-Type": "application/zip",
          "X-Gravit-Profile-Path": contentProfilePath,
          "X-Profile-ID": contentProfileId,
          "X-Profile-Name": contentProfileName,
          "X-Loader": contentLoader,
          "X-Channel": contentChannel,
          "X-Version": contentVersion,
        }, body: source },
      );
      setMigrationPlan0442(result);
      setContentPreview(result.content);
      await refresh(runId);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  const planMatches0442 = Boolean(
    migrationPlan0442 && inventory &&
    migrationPlan0442.sourceSha256 === inventory.sourceSha256 &&
    migrationPlan0442.destination.profilePath === contentProfilePath &&
    migrationPlan0442.destination.profileId === contentProfileId &&
    migrationPlan0442.destination.profileName === contentProfileName &&
    migrationPlan0442.destination.loader === contentLoader &&
    migrationPlan0442.destination.channel === contentChannel &&
    migrationPlan0442.destination.version === contentVersion &&
    migrationPlan0442.targetUnchanged !== false
  );
  async function migrationContent0337(commit: boolean) {
    if (!runId || !source || !inventory || busy) return;
    if (commit && (!contentPreview?.ready || contentConfirm !== runId || !planMatches0442 || migrationPlan0442?.status === "blocked")) {
      setError("Для переноса необходимо подтвердить текущий план и ID запуска");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const headers = {
        "Content-Type": "application/zip",
        "X-Gravit-Profile-Path": contentProfilePath,
        "X-Profile-ID": contentProfileId,
        "X-Profile-Name": contentProfileName,
        "X-Loader": contentLoader,
        "X-Channel": contentChannel,
        "X-Version": contentVersion,
        ...(commit ? { "X-Migration-Content-Confirm": runId, "X-Migration-Plan-SHA256": migrationPlan0442!.planSha256 } : {}),
      };
      const result = await requestJSON<ContentPlan0337 | ContentState0337>(
        backendUrl,
        `${base}/${encodeURIComponent(runId)}/content/${commit ? "import" : "preview"}`,
        token,
        { method: "POST", headers, body: source },
      );
      if (commit) {
        setContentState(result as ContentState0337);
        setContentPreview(null);
        setContentConfirm("");
      } else {
        setContentPreview(result as ContentPlan0337);
        setContentState(null);
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  async function refreshMigrationContent0337() {
    if (!runId || !contentProfilePath || busy) return;
    setBusy(true);
    setError("");
    try {
      setContentState(
        await requestJSON<ContentState0337>(
          backendUrl,
          `${base}/${encodeURIComponent(runId)}/content?profilePath=${encodeURIComponent(contentProfilePath)}`,
          token,
        ),
      );
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  async function applyOptionals0337() {
    if (!runId || !contentProfilePath || busy || contentConfirm !== runId)
      return;
    setBusy(true);
    setError("");
    try {
      await requestJSON<unknown>(
        backendUrl,
        `${base}/${encodeURIComponent(runId)}/content/apply-optionals?profilePath=${encodeURIComponent(contentProfilePath)}`,
        token,
        { method: "POST", headers: { "X-Migration-Content-Confirm": runId } },
      );
      await refresh(runId);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  async function exportSource() {
    if (!runId || !source || busy || !inventory) return;
    if (source.size < 1 || source.size > 512 * 1024 * 1024) {
      setError("Размер ZIP должен быть от 1 до 512 МиБ");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const response = await fetch(
        `${backendUrl.replace(/\/$/, "")}${base}/${encodeURIComponent(runId)}/export`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/zip",
          },
          body: source,
          cache: "no-store",
          redirect: "error",
        },
      );
      if (!response.ok) {
        const payload = await response.text();
        throw new Error(
          `Ошибка экспорта, HTTP ${response.status}: ${payload.slice(0, 250)}`,
        );
      }
      if (
        response.headers.get("X-Migration-Manifest-SHA256") !==
        inventory.manifestSha256
      )
        throw new Error("Манифест экспорта не совпадает");
      if (
        !(response.headers.get("Content-Type") || "").startsWith(
          "application/zip",
        )
      )
        throw new Error("Неожиданный ответ при экспорте");
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      try {
        const link = document.createElement("a");
        link.href = url;
        link.download = `gravit-source-${runId}.zip`;
        document.body.appendChild(link);
        link.click();
        link.remove();
      } finally {
        URL.revokeObjectURL(url);
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  async function inspectModules0338() {
    if (!runId || !source || !inventory || busy) return;
    setBusy(true);
    setError("");
    try {
      const result = await requestJSON<Modules0338>(
        backendUrl,
        `${base}/${encodeURIComponent(runId)}/modules/analyze`,
        token,
        {
          method: "POST",
          headers: { "Content-Type": "application/zip" },
          body: source,
        },
      );
      setModules0338(result);
      await refresh(runId);
    } catch (e) {
      setError(String(e));
      await refresh(runId).catch(() => undefined);
    } finally {
      setBusy(false);
    }
  }
  async function checkBridge0446() {
    if (!runId || !wrapperPath0338 || busy) return;
    setBusy(true);
    setError("");
    try {
      const status = await requestJSON<BridgeStatus0446>(
        backendUrl,
        `${base}/${encodeURIComponent(runId)}/modules/serverbridge-status?wrapperPath=${encodeURIComponent(wrapperPath0338)}`,
        token,
      );
      setBridgeStatus0446(status);
    } catch (e) {
      setBridgeStatus0446(null);
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  async function enrollBridge0338() {
    if (
      !runId ||
      !modules0338?.ready ||
      bridgeConfirm0338 !== runId ||
      !bridgeFreshKeys0338 ||
      busy
    )
      return;
    setBusy(true);
    setError("");
    try {
      await requestJSON(
        backendUrl,
        `${base}/${encodeURIComponent(runId)}/modules/enroll-serverbridge`,
        token,
        {
          method: "POST",
          headers: {
            "X-Migration-Modules-Confirm": runId,
            "X-Migration-Fresh-Keys-Confirmed": "true",
          },
          body: JSON.stringify({
            wrapperPath: wrapperPath0338,
            id: bridgeNode0338,
            name: bridgeName0338,
            kind: bridgeKind0338,
            profileId: migrationPlan0442?.destination.profileId ?? bridgeProfile0338,
            publicKey: bridgePublicKey0338,
          }),
        },
      );
      setBridgeConfirm0338("");
      setBridgePublicKey0338("");
      setBridgeFreshKeys0338(false);
      setBridgeStatus0446(null);
      await refresh(runId);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="card wide" aria-label="Центр миграции 0.33.7">
      <h2>Центр миграции · 0.33.7</h2>
      <p>
        Durable workflow для проверки целевого проекта Never и фиксации
        инвентаризации. Статус «prepared» означает только сохранённый baseline;
        совместимость Gravit анализируется отдельно по ZIP; импорт
        поддерживаемых учётных записей доступен отдельно. Переключение не
        выполняется.
      </p>
      <form onSubmit={(e) => void create(e)} className="subcard">
        <label className="field">
          <span>Проект назначения</span>
          <input value={projectId} readOnly />
        </label>
        <label className="field">
          <span>Ключ идемпотентности (сохраните до завершения операции)</span>
          <input
            value={key}
            minLength={8}
            maxLength={128}
            required
            onChange={(e) => setKey(e.target.value)}
            placeholder="change-request-2026-001"
          />
        </label>
        <button type="submit" disabled={busy || !projectId || key.length < 8}>
          Создать или найти запуск
        </button>
      </form>
      <label className="field">
        <span>Запуск</span>
        <select
          value={runId}
          onChange={(e) => {
            setRunId(e.target.value);
            void refresh(e.target.value).catch((err) => setError(String(err)));
          }}
        >
          <option value="">Выберите запуск миграции</option>
          {runs.map((item) => (
            <option key={item.id} value={item.id}>
              {item.id} · {statusRu(item.status)} · {statusRu(item.step)}
            </option>
          ))}
        </select>
      </label>
      <div className="buttonRow">
        <button
          disabled={busy || !runId}
          onClick={() => void refresh(runId).catch((e) => setError(String(e)))}
        >
          Обновить
        </button>
        <button
          disabled={
            busy ||
            !runId ||
            !run ||
            !["pending", "running"].includes(run.status)
          }
          onClick={() => void operate("execute")}
        >
          Выполнить baseline
        </button>
        <button
          disabled={
            busy ||
            !runId ||
            !run ||
            !["pending", "failed", "running"].includes(run.status)
          }
          onClick={() => void operate("pause")}
        >
          Пауза
        </button>
        <button
          disabled={
            busy || !runId || !run || !["paused", "failed"].includes(run.status)
          }
          onClick={() => void operate("resume")}
        >
          Возобновить
        </button>
      </div>
      {run && (
        <form onSubmit={(e) => void assess(e)} className="subcard">
          <h3>Проверка совместимости Gravit</h3>
          <p>
            Архив исходного проекта (LaunchServer.json, profiles/, runtime,
            modules/). Конфигурации и секреты не сохраняются на сервере.
            Неизвестные модули требуют проверки. Даже отчёт без блокеров не
            разрешает переключение.
          </p>
          <label className="field">
            <span>ZIP проекта Gravit (максимум 512 MiB)</span>
            <input
              type="file"
              required
              accept=".zip,application/zip"
              onChange={(e) => {
                setSource(e.target.files?.[0] ?? null);
                setCredentialPreview(null);
                setMigrationPlan0442(null);
                setConfirmRun("");
              }}
            />
          </label>
          <label className="field">
            <span>
              Предполагаемая версия Gravit (не является подтверждением)
            </span>
            <input
              value={claimedVersion}
              maxLength={40}
              onChange={(e) => setClaimedVersion(e.target.value)}
              placeholder="5.7.12"
            />
          </label>
          <button
            type="submit"
            disabled={
              busy ||
              !source ||
              run.status !== "prepared" ||
              run.step !== "source_assessment"
            }
          >
            Проверить ZIP и сохранить отчёт
          </button>
        </form>
      )}
      {run && (
        <article className="subcard">
          <h3>Инвентаризация исходников и экспорт · MIG03</h3>
          <p>
            Инвентаризация использует выбранный ZIP (до 512 MiB), проверяет
            каждый файл и сохраняет только контрольные суммы и категории. Для
            экспорта нужно повторно предоставить тот же ZIP. Экспорт может
            содержать пароли и ключи: храните его в защищённом месте.
          </p>
          <div className="buttonRow">
            <button
              disabled={
                busy ||
                !source ||
                run.status !== "prepared" ||
                run.step !== "source_assessment"
              }
              onClick={() => void inventorySource()}
            >
              Инвентаризировать и сохранить
            </button>
            <button
              disabled={
                busy || !source || !inventory || run.status !== "prepared"
              }
              onClick={() => void exportSource()}
            >
              Экспортировать проверенный ZIP
            </button>
          </div>
          {inventory && (
            <>
              <p>
                Файлы: {inventory.sourceEntries}; распаковано:{" "}
                {inventory.totalBytes} байт; чувствительных файлов:{" "}
                {inventory.sensitiveEntries}; серверных записей:{" "}
                {inventory.serverReferences}.
              </p>
              <p>
                SHA-256 источника: <code>{inventory.sourceSha256}</code>
              </p>
              <p>
                SHA-256 манифеста: <code>{inventory.manifestSha256}</code>
              </p>
              <p>
                Категории: {JSON.stringify(inventory.categories)}; провайдеры
                авторизации: {JSON.stringify(inventory.authProviders)}; дополнительные
                действия: {JSON.stringify(inventory.optionalActions)}
              </p>
              <details>
                <summary>Все файлы и контрольные суммы</summary>
                <pre>{JSON.stringify(inventory.files, null, 2)}</pre>
              </details>
            </>
          )}
        </article>
      )}
      {run && (
        <article className="subcard">
          <h3>Сопоставление идентичности и UUID · MIG04</h3>
          <p>
            Читает FileAuthSystem/Database.json либо sql-export/users.csv из
            исходного ZIP. Сопоставляет UUID с Never, блокирует конфликтные
            идентичности и не импортирует пароли. Для SQL нужен нормализованный
            CSV со столбцами id,username,uuid.
          </p>
          <div className="buttonRow">
            <button
              disabled={
                busy || !source || !inventory || run.status !== "prepared"
              }
              onClick={() => void mapIdentities()}
            >
              Построить карту UUID
            </button>
            <button
              disabled={busy || !identities || run.status !== "prepared"}
              onClick={() => void verifyIdentities()}
            >
              Повторно сверить с Never
            </button>
          </div>
          {identities && (
            <>
              <p>
                Совпало: {identities.summary.matched ?? 0}; ожидает импорта:{" "}
                {identities.summary.pending_import ?? 0}; заблокировано:{" "}
                {identities.summary.blocked ?? 0}. Все сопоставлены:{" "}
                {identities.ready ? "да" : "нет"}. Это не разрешение на переключение.
              </p>
              <details>
                <summary>Сопоставление UUID ({identities.rows.length})</summary>
                <pre>{JSON.stringify(identities.rows, null, 2)}</pre>
              </details>
            </>
          )}
        </article>
      )}
      {run && (
        <article className="subcard">
          <h3>Миграция аутентификации · MIG05</h3>
          <p>
            Импортируются только новые local-аккаунты с проверенными исходными
            UUID и поддерживаемыми хешами. SQL: sql-export/users.csv с
            id,username,uuid,password_format,password_hash. Существующие
            аккаунты Never не перезаписываются. Отсутствующий или неизвестный
            формат пароля FileAuth, а также неподдерживаемые SQL-хеши требуют
            индивидуальной подтверждённой смены пароля. Такие пользователи не
            создаются с пустым паролем и блокируют готовность к переключению.
          </p>
          <label className="field">
            <span>
              Формат хеша FileAuthSystem (выберите по исходной конфигурации;
              неизвестный формат означает ручную смену пароля)
            </span>
            <select
              value={passwordFormat}
              onChange={(e) => {
                setPasswordFormat(e.target.value);
                setCredentialPreview(null);
              }}
            >
              {[
                "",
                "sha256-hex",
                "sha256-base64url",
                "md5-hex",
                "sha1-hex",
                "sha512-hex",
                "double-sha256-hex",
                "double-sha256-binary-hex",
                "phpass",
                "bcrypt",
                "argon2id",
              ].map((x) => (
                <option key={x} value={x}>
                  {x || "Неизвестен / только SQL (FileAuth — ручной сброс)"}
                </option>
              ))}
            </select>
          </label>
          <div className="buttonRow">
            <button
              disabled={
                busy ||
                !source ||
                !identities ||
                identities.summary.blocked > 0 ||
                run.status !== "prepared"
              }
              onClick={() => void migrationCredentials(false)}
            >
              Проверить импорт паролей (пробная проверка)
            </button>
          </div>
          {credentialPreview && (
            <>
              <p>
                Пробный запуск: будет импортировано {credentialPreview.imported},
                существующих без изменений {credentialPreview.existingUnchanged}
                , индивидуальный сброс {credentialPreview.manualReset}.
              </p>
              {credentialPreview.rows.some((row) => row.state !== "imported") && (
                <details>
                  <summary>Учётные записи, требующие отдельного решения (первые 50)</summary>
                  <ul>
                    {credentialPreview.rows
                      .filter((row) => row.state !== "imported")
                      .slice(0, 50)
                      .map((row) => (
                        <li key={`${row.provider}:${row.sourceId}:${row.uuid}`}>
                          {row.username} ({row.uuid}): {statusRu(row.reason || row.state)}
                        </li>
                      ))}
                  </ul>
                </details>
              )}
              <label className="field">
                <span>Для подтверждения введите ID запуска</span>
                <input
                  value={confirmRun}
                  onChange={(e) => setConfirmRun(e.target.value)}
                  placeholder={runId}
                />
              </label>
              <button
                disabled={
                  busy || confirmRun !== runId || run.status !== "prepared"
                }
                onClick={() => void migrationCredentials(true)}
              >
                Подтверждаю реальный импорт аккаунтов
              </button>
            </>
          )}
          <h3>Сброс безопасности и доверия · 0.33.6</h3>
          <p>
            Для новых импортированных пользователей: транзакционный отзыв всех
            старых сеансов Never, привязок устройств, challenges,
            TPM/measured-boot доказательств. Уже существующие аккаунты не
            изменяются. Внешние ключи Gravit не импортируются. Переключение запрещено.
          </p>
          <div className="buttonRow">
            <button
              disabled={busy || !credentials || run.status !== "prepared"}
              onClick={() => void migrationSecurity0336(false)}
            >
              Предварительная проверка reset
            </button>
            <button disabled={busy} onClick={() => void verifySecurity0336()}>
              Проверить security receipt
            </button>
          </div>
          {securityPreview && (
            <>
              <p>
                Предварительный reset для {securityPreview.importedAccounts}{" "}
                импортированных аккаунтов. Существующие аккаунты без изменений:{" "}
                {securityPreview.existingNeverUntouched}. KID:{" "}
                {securityPreview.activeJwtKid}; SHA-256 публичного ключа:{" "}
                {securityPreview.manifestPublicSha256}.
              </p>
              <label className="field">
                <span>Введите точный run ID</span>
                <input
                  value={securityRunConfirm}
                  onChange={(e) => setSecurityRunConfirm(e.target.value)}
                  autoComplete="off"
                />
              </label>
              <label className="field">
                <input
                  type="checkbox"
                  checked={freshKeysConfirmed}
                  onChange={(e) => setFreshKeysConfirmed(e.target.checked)}
                />{" "}
                Подтверждаю, что активный JWT secret и manifest Ed25519 seed
                Never созданы независимо от Gravit и доставлены через защищённое
                хранилище секретов
              </label>
              <button
                disabled={
                  busy || securityRunConfirm !== runId || !freshKeysConfirmed
                }
                onClick={() => void migrationSecurity0336(true)}
              >
                Применить отзыв доверия
              </button>
            </>
          )}
          {security && (
            <p>
              Сброс параметров безопасности: {security.verified ? "проверен" : "зафиксирован"}{" "}
              · отозвано сеансов: {security.sessionsRevoked} · устройств:{" "}
              {security.devicesRevoked} · запросов проверки:{" "}
              {security.challengesConsumed}. Требуются повторный вход, регистрация устройства и новая аттестация Guard.
            </p>
          )}
          {credentials && (
            <p>
              Зафиксированный результат: импортировано {credentials.imported},
              существующих не изменено {credentials.existingUnchanged}, сброс
              пароля требуется {credentials.manualReset}. Это не разрешение на
              cutover.
            </p>
          )}
          {(credentialPreview || credentials) && (
            <details>
              <summary>Отчёт (без секретов)</summary>
              <pre>
                {JSON.stringify(credentialPreview || credentials, null, 2)}
              </pre>
            </details>
          )}
        </article>
      )}
      {run && (
        <article className="subcard">
          <h3>Миграция содержимого и профиля · MIG07</h3>
          <p>
            Проверяемый перенос одного Gravit ClientProfile и содержимого
            updates/&lt;dir&gt;, clients/&lt;dir&gt;, libraries/,
            assets/ в зашифрованный Never Build Workspace. Импортёр использует
            поле <code>dir</code> Gravit ClientProfile, если оно задано;
            пользовательские файлы не копируются. Каждый запуск миграции
            закрепляет один профиль и собственный пробный запуск. Сервер не выполняет
            исходные JAR и не копирует авторизацию, ключи или модули. Новый
            релиз подписывается только после отдельной проверки.
          </p>
          <label className="field">
            <span>Путь профиля в ZIP</span>
            <input
              value={contentProfilePath}
              list="gravit-profile-paths-0443"
              onChange={(e) => {
                setContentProfilePath(e.target.value);
                setContentPreview(null);
                setContentState(null);
              }}
            />
            <datalist id="gravit-profile-paths-0443">
              {(inventory?.files ?? []).filter((f) => f.kind === "client_profile").map((f) =>
                <option key={f.path} value={f.path} />
              )}
            </datalist>
            {inventory && <span className="muted">Профилей в проверенном ZIP: {inventory.files.filter((f) => f.kind === "client_profile").length}. Выберите точный путь из списка; для другого профиля создайте отдельный запуск миграции.</span>}
          </label>
          <label className="field">
            <span>ID нового профиля Never</span>
            <input
              value={contentProfileId}
              onChange={(e) => {
                setContentProfileId(e.target.value);
                setContentPreview(null);
              }}
            />
          </label>
          <label className="field">
            <span>Название</span>
            <input
              value={contentProfileName}
              onChange={(e) => {
                setContentProfileName(e.target.value);
                setContentPreview(null);
              }}
            />
          </label>
          <label className="field">
            <span>Загрузчик</span>
            <select
              value={contentLoader}
              onChange={(e) => {
                setContentLoader(e.target.value);
                setContentPreview(null);
              }}
            >
              {["vanilla", "fabric", "quilt", "forge", "neoforge"].map((x) => (
                <option key={x}>{x}</option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Канал</span>
            <input
              value={contentChannel}
              onChange={(e) => {
                setContentChannel(e.target.value);
                setContentPreview(null);
              }}
            />
          </label>
          <label className="field">
            <span>Версия нового релиза</span>
            <input
              value={contentVersion}
              onChange={(e) => {
                setContentVersion(e.target.value);
                setContentPreview(null);
              }}
            />
          </label>
          <div className="buttonRow">
            <button
              disabled={busy || !source || !inventory || !compatibility || run.status !== "prepared"}
              onClick={() => void migrationDryRun0442()}
            >
              Выполнить полную пробную проверку и зафиксировать план
            </button>
            <button
              disabled={
                busy || !source || !inventory || run.status !== "prepared"
              }
              onClick={() => void migrationContent0337(false)}
            >
              Проверить профиль и реальные файлы
            </button>
            <button
              disabled={busy || !runId}
              onClick={() => void refreshMigrationContent0337()}
            >
              Проверить сохранённое состояние
            </button>
          </div>
          {migrationPlan0442 && (
            <div>
              <p>Общий план: <strong>{statusRu(migrationPlan0442.status)}</strong>;
                совпадение с текущими полями: {planMatches0442 ? "да" : "нет, требуется новая пробная проверка"}.
                Исходная цель: {migrationPlan0442.targetUnchanged === false ? "изменилась — повторить пробную проверку" : "актуальна"}.
                Учётных записей: {migrationPlan0442.identities.sourceAccounts};
                проблем сопоставления UUID: {migrationPlan0442.identities.duplicateOrConflicting}.
                Копирование: {migrationPlan0442.transferBytes} байт;
                автоматических: {migrationPlan0442.counts.automatic || 0};
                преобразований: {migrationPlan0442.counts.transformed || 0};
                ручных: {migrationPlan0442.counts.manual || 0};
                блокирующих: {migrationPlan0442.blockers.length}.
              </p>
              <p>SHA-256 плана: <code>{migrationPlan0442.planSha256}</code></p>
              {migrationPlan0442.blockers.map((x, i) => <p key={i} className="error">{x}</p>)}
              <details>
                <summary>Работы оператора и полный список операций</summary>
                <ul>{migrationPlan0442.checklist.map((x) => <li key={x.action}>{x.detail}</li>)}</ul>
                <pre>{JSON.stringify(migrationPlan0442.items, null, 2)}</pre>
              </details>
            </div>
          )}
          {contentPreview && (
            <>
              <p>
                Профиль:{" "}
                {contentPreview.ready ? "может быть перенесён" : "заблокирован"}
                , каталог исходного клиента: <code>{contentPreview.sourceDirectory || "не определён"}</code>;
                файлов: {contentPreview.files.length}; пропущено (не копируется): {contentPreview.skippedFiles?.length ?? 0}, дополнительные:{" "}
                {contentPreview.optional?.ready
                  ? "преобразованы"
                  : contentPreview.optional
                    ? "есть блокеры"
                    : "не заданы"}
                .
              </p>
              {contentPreview.blockers.map((x, i) => (
                <p key={i} className="error">
                  {x}
                </p>
              ))}
              {Boolean(contentPreview.skippedFiles?.length) && <details>
                <summary>Файлы, оставленные на стороне Gravit / игрока ({contentPreview.skippedFiles?.length ?? 0})</summary>
                <ul>{contentPreview.skippedFiles?.map((f) =>
                  <li key={f.sourcePath}><code>{f.sourcePath}</code> — {f.reason}</li>
                )}</ul>
              </details>}
              <details>
                <summary>План, поля и SHA-256</summary>
                <pre>{JSON.stringify(contentPreview, null, 2)}</pre>
              </details>
              {contentPreview.ready && (
                <>
                  <label className="field">
                    <span>Введите точный run ID перед переносом файлов</span>
                    <input
                      autoComplete="off"
                      value={contentConfirm}
                      onChange={(e) => setContentConfirm(e.target.value)}
                    />
                  </label>
                  <button
                    disabled={busy || contentConfirm !== runId || !planMatches0442 || migrationPlan0442?.status === "blocked"}
                    onClick={() => void migrationContent0337(true)}
                  >
                    Перенести реальные файлы в зашифрованный Build Workspace
                  </button>
                </>
              )}
            </>
          )}
          {contentState && (
            <>
              <p>
                Рабочая область: <code>{contentState.workspaceId}</code>; сохранено{" "}
                {contentState.stagedFiles}/{contentState.totalFiles} файлов;
                состояние: {statusRu(contentState.state)}.
              </p>
              <p>
                Проверка:{" "}
                {contentState.validation || "требуется повторная проверка"}.
                Сборка и подпись выполняются через стандартные операции
                рабочей области сборки и управления пакетами.
              </p>
              {contentState.plan.optional && (
                <button
                  disabled={
                    busy ||
                    contentConfirm !== runId ||
                    contentState.state !== "built"
                  }
                  onClick={() => void applyOptionals0337()}
                >
                  Применить проверенный каталог необязательных компонентов к неподписанному черновику
                </button>
              )}
            </>
          )}
        </article>
      )}
      {run && (
        <article className="subcard">
          <h3>Миграция модулей и ServerWrapper · MIG08</h3>
          <p>
            Статическая проверка JAR без запуска. Неизвестные исполняемые модули
            блокируют миграцию до переноса исходников либо сертифицированного
            адаптера. Старые токены ServerWrapper не применяются.
          </p>
          <button
            disabled={
              busy || !source || !inventory || run.status !== "prepared"
            }
            onClick={() => void inspectModules0338()}
          >
            Проверить модули и ServerWrapper
          </button>
          {modules0338 && (
            <>
              <p>
                Модулей: {modules0338.modules.length}, ServerWrapper:{" "}
                {modules0338.wrappers.length}, блокеров:{" "}
                {modules0338.blockers.length}. Переключение запрещено.
              </p>
              {modules0338.blockers.map((x, i) => (
                <p key={i} className="error">
                  {x}
                </p>
              ))}
              <details>
                <summary>Модули, SHA-256 и ServerWrapper</summary>
                <pre>{JSON.stringify(modules0338, null, 2)}</pre>
              </details>
              {modules0338.ready && modules0338.wrappers.length > 0 && (
                <>
                  <p>
                    Для подключения ServerBridge необходим новый открытый ключ
                    Ed25519; закрытый ключ остаётся на игровом сервере.
                    Регистрация не заменяет проверку входа и подключения к игре.
                  </p>
                  <label className="field">
                    <span>Файл ServerWrapper из отчёта</span>
                    <select
                      value={wrapperPath0338}
                      onChange={(e) => {
                        setWrapperPath0338(e.target.value);
                        setBridgeStatus0446(null);
                      }}
                    >
                      <option value="">Выберите</option>
                      {modules0338.wrappers.map((x) => (
                        <option key={x.path}>{x.path}</option>
                      ))}
                    </select>
                  </label>
                  <label className="field">
                    <span>Идентификатор нового узла ServerBridge</span>
                    <input
                      value={bridgeNode0338}
                      onChange={(e) => setBridgeNode0338(e.target.value)}
                    />
                  </label>
                  <label className="field">
                    <span>Название</span>
                    <input
                      value={bridgeName0338}
                      onChange={(e) => setBridgeName0338(e.target.value)}
                    />
                  </label>
                  <label className="field">
                    <span>Тип</span>
                    <select
                      value={bridgeKind0338}
                      onChange={(e) => setBridgeKind0338(e.target.value)}
                    >
                      {[
                        "paper",
                        "purpur",
                        "spigot",
                        "bukkit",
                        "fabric",
                        "forge",
                        "neoforge",
                        "velocity",
                        "bungeecord",
                        "waterfall",
                        "vanilla",
                      ].map((x) => (
                        <option key={x}>{x}</option>
                      ))}
                    </select>
                  </label>
                  <label className="field">
                    <span>Новый профиль Never</span>
                    <input
                      value={migrationPlan0442?.destination.profileId ?? bridgeProfile0338}
                      readOnly={Boolean(migrationPlan0442?.destination.profileId)}
                      onChange={(e) => setBridgeProfile0338(e.target.value)}
                    />
                  </label>
                  <label className="field">
                    <span>Новый открытый ключ Ed25519 (base64url)</span>
                    <input
                      value={bridgePublicKey0338}
                      onChange={(e) => setBridgePublicKey0338(e.target.value)}
                    />
                  </label>
                  <label className="field">
                    <input
                      type="checkbox"
                      checked={bridgeFreshKeys0338}
                      onChange={(e) => setBridgeFreshKeys0338(e.target.checked)}
                    />{" "}
                    Новая независимая пара ключей Ed25519 для Never, не унаследованная
                    от Gravit
                  </label>
                  <label className="field">
                    <span>
                      Введите точный ID запуска (требуется новая сессия с многофакторной проверкой)
                    </span>
                    <input
                      value={bridgeConfirm0338}
                      onChange={(e) => setBridgeConfirm0338(e.target.value)}
                    />
                  </label>
                  <button
                    disabled={
                      busy ||
                      !wrapperPath0338 ||
                      !bridgeNode0338 ||
                      !(migrationPlan0442?.destination.profileId ?? bridgeProfile0338) ||
                      !bridgePublicKey0338 ||
                      bridgeConfirm0338 !== runId ||
                      !bridgeFreshKeys0338
                    }
                    onClick={() => void enrollBridge0338()}
                  >
                    Зарегистрировать новый узел ServerBridge
                  </button>
                  <p>После установки ServerBridge на игровой сервер проверьте реальный подписанный сигнал состояния. Регистрация ключа не означает готовность к переключению.</p>
                  <button disabled={busy || !wrapperPath0338} onClick={() => void checkBridge0446()}>
                    Проверить подключение ServerBridge
                  </button>
                  {bridgeStatus0446 && (
                    <p role="status">
                      Узел {bridgeStatus0446.serverId}: {statusRu(bridgeStatus0446.state)} ({statusRu(bridgeStatus0446.reason)}).
                      Даже при подключённом узле требуется проверить вход в игру и подключение к серверу перед переключением.
                    </p>
                  )}
                </>
              )}
            </>
          )}
        </article>
      )}
      {run && (
        <article className="subcard">
          <h3>Изолированная репетиция миграции · MIG10</h3>
          <p>
            Проверки исполняются CLI на отдельном изолированном стенде. Backend
            сверяет результаты с MIG03–MIG08 и UUID из сохранённой карты.
            Административный сервер не запускает JAR или команды из браузера.
            Для репетиции 0.44.7 нужен работающий изолированный Java-сервер с локальным RCON, настоящий клиентский процесс и live-session.json со staging-учётной записью. Успешные probe-скрипты без реального входа и online UUID больше не дают допуск. Инструкция: docs/migration/gravit-live-rehearsal.md.
          </p>
          <p>
            <code>
              nl migrate gravit rehearse --run {runId} --stage
              /srv/staging-rehearsal --inventory-sha256
              &lt;MIG03-manifest-sha256&gt; --backend https://your-backend
              --token &lt;token&gt;
            </code>
          </p>
          <button disabled={busy} onClick={() => void refresh(runId)}>
            Прочитать последнюю репетицию
          </button>
          {rehearsal03310 && (
            <>
              <p>
                Стенд: <code>{rehearsal03310.stageId}</code> · проверок:{" "}
                {rehearsal03310.probes.length} · результат:{" "}
                {rehearsal03310.ready ? "пройдена" : "заблокирована"} · переключение:
                запрещено.
              </p>
              {rehearsal03310.liveSession ? (
                <p>Игровой сеанс: {rehearsal03310.liveSession.playerName} / <code>{rehearsal03310.liveSession.playerUuid}</code> · вход: {rehearsal03310.liveSession.joinedAt} · клиент SHA-256: <code>{rehearsal03310.liveSession.clientSha256}</code></p>
              ) : (
                <p className="error">Нет нативного подтверждения живого игрового сеанса. Старые отчёты, основанные только на пробных проверках, не считаются подтверждением готовности.</p>
              )}
              {rehearsal03310.blockers.map((x, i) => (
                <p key={i} className="error">
                  {x}
                </p>
              ))}
              <details>
                <summary>SHA-256, UUID и результаты проверок</summary>
                <pre>{JSON.stringify(rehearsal03310, null, 2)}</pre>
              </details>
            </>
          )}
        </article>
      )}
      {run && (
        <article className="subcard">
          <h3>Подготовленное переключение · MIG11</h3>
          <p>
            Переключает рабочий указатель <code>channel_heads</code> на
            проверенный и подписанный релиз Never. Пока канал staged, PostgreSQL
            блокирует другие публикации. Исходный процесс записи Gravit необходимо
            остановить и проверить отдельно: Never не умеет подтвердить его
            отключение.
          </p>
          <label className="field">
            <span>Профиль</span>
            <input
              value={cutoverProfile03311}
              onChange={(e) => setCutoverProfile03311(e.target.value)}
            />
          </label>
          <label className="field">
            <span>Канал</span>
            <input
              value={cutoverChannel03311}
              onChange={(e) => setCutoverChannel03311(e.target.value)}
            />
          </label>
          <label className="field">
            <span>ID подписанного опубликованного релиза этой миграции</span>
            <input
              value={cutoverRelease03311}
              onChange={(e) => setCutoverRelease03311(e.target.value)}
            />
          </label>
          <label className="field">
            <span>Текущая ревизия channel_head (0, если канал пуст)</span>
            <input
              type="number"
              min="0"
              value={cutoverHeadRev03311}
              onChange={(e) => setCutoverHeadRev03311(e.target.value)}
            />
          </label>
          <label className="field">
            <span>Подтверждение: точный идентификатор задачи миграции</span>
            <input
              value={cutoverConfirm03311}
              onChange={(e) => setCutoverConfirm03311(e.target.value)}
            />
          </label>
          <button
            disabled={
              busy ||
              cutoverConfirm03311 !== runId ||
              !cutoverProfile03311 ||
              !cutoverRelease03311 ||
              !rehearsal03310?.ready
            }
            onClick={() => void cutoverAction03311("stage")}
          >
            Stage: заморозить публикацию канала
          </button>
          <p>
            Для активации сохраните независимо полученные доказательства
            отключения записи Gravit (операционный журнал/акт и его SHA-256).
            Флаг оператора не является автоматической проверкой исходного
            сервера.
          </p>
          <label className="field">
            <span>JSON-квитанция фиксации исходного состояния, полученная командой verify-source-fence после остановки Gravit</span>
            <textarea rows={5} value={cutoverReceipt0448} onChange={(e) => setCutoverReceipt0448(e.target.value)} />
          </label>
          <label className="field">
            <span>Ссылка на подтверждение фиксации исходного состояния</span>
            <input
              value={cutoverFenceRef03311}
              onChange={(e) => setCutoverFenceRef03311(e.target.value)}
            />
          </label>
          <label className="field">
            <span>SHA-256 доказательства</span>
            <input
              value={cutoverFenceSha03311}
              onChange={(e) => setCutoverFenceSha03311(e.target.value)}
            />
          </label>
          <label className="field">
            <span>
              SHA-256 свежего исходного снимка состояния (должен совпасть с MIG10)
            </span>
            <input
              value={cutoverSnapshot03311}
              onChange={(e) => setCutoverSnapshot03311(e.target.value)}
            />
          </label>
          <label className="field">
            <input
              type="checkbox"
              checked={cutoverSourceStopped03311}
              onChange={(e) => setCutoverSourceStopped03311(e.target.checked)}
            />{" "}
            Исходный процесс записи Gravit остановлен и независимо проверен оператором
          </label>
          {cutovers03311.map((route) => (
            <div key={`${route.profileId}/${route.channel}`}>
              <p>
                <code>
                  {route.profileId}/{route.channel}
                </code>{" "}
                · {statusRu(route.state)} · ревизия {route.revision} · выпуск NeverLauncher{" "}
                <code>{route.releaseId}</code> · исходная ревизия{" "}
                {route.baselineRevision} · активная ревизия{" "}
                {route.activatedRevision ?? "—"}
              </p>
              {route.state === "staged" && (
                <>
                  <button
                    disabled={
                      busy ||
                      cutoverConfirm03311 !== runId ||
                      !cutoverSourceStopped03311 ||
                      !cutoverReceipt0448.trim() ||
                      !cutoverFenceRef03311 ||
                      !/^[a-f0-9]{64}$/.test(cutoverFenceSha03311) ||
                      !/^[a-f0-9]{64}$/.test(cutoverSnapshot03311)
                    }
                    onClick={() => void cutoverAction03311("activate", route)}
                  >
                    Activate: переключить реальный канал
                  </button>
                  <button
                    disabled={busy || cutoverConfirm03311 !== runId}
                    onClick={() => void cutoverAction03311("cancel", route)}
                  >
                    Отменить подготовку без изменения релиза
                  </button>
                </>
              )}
              {route.state === "active" && (
                <div>
                  <h4>Эксплуатационный откат · MIG12</h4>
                  <p>
                    Только безопасное обратное переключение Never. Перед планом
                    остановите запись Never и обоих игровых серверов вне панели;
                    подготовьте JSON свежего снимка состояния мира, UUID, инвентаря,
                    прав и экономики. При изменениях данных требуется внешняя
                    сверка/перенос новых записей в Gravit: укажите также новый
                    снимок согласованного Gravit и SHA-256 доказательства.
                    Несовпадающие данные блокируют возврат. Снимки никогда не
                    восстанавливаются поверх изменившихся миров.
                  </p>
                  <label className="field">
                    <span>
                      Актуальный снимок состояния в формате JSON из независимо остановленного
                      окружения
                    </span>
                    <textarea
                      rows={7}
                      value={rollbackSnapshot03312}
                      onChange={(e) => setRollbackSnapshot03312(e.target.value)}
                    />
                  </label>
                  <label className="field">
                    <span>
                      Опционально: JSON снимка Gravit после внешней сверки новых
                      записей
                    </span>
                    <textarea
                      rows={5}
                      value={rollbackSourceSnapshot03312}
                      onChange={(e) =>
                        setRollbackSourceSnapshot03312(e.target.value)
                      }
                    />
                  </label>
                  <label className="field">
                    <span>
                      SHA-256 доказательства переноса новых записей в Gravit
                    </span>
                    <input
                      value={rollbackReconcileHash03312}
                      onChange={(e) =>
                        setRollbackReconcileHash03312(e.target.value)
                      }
                    />
                  </label>
                  <label className="field">
                    <span>
                      Ссылка на внешнее доказательство целостности/остановки
                    </span>
                    <input
                      value={rollbackRef03312}
                      onChange={(e) => setRollbackRef03312(e.target.value)}
                    />
                  </label>
                  <label className="field">
                    <span>SHA-256 доказательства свежего снимка</span>
                    <input
                      value={rollbackHash03312}
                      onChange={(e) => setRollbackHash03312(e.target.value)}
                    />
                  </label>
                  <label className="field">
                    <input
                      type="checkbox"
                      checked={rollbackNeverFenced03312}
                      onChange={(e) =>
                        setRollbackNeverFenced03312(e.target.checked)
                      }
                    />{" "}
                    Процессы записи Never и игры остановлены оператором
                  </label>
                  <label className="field">
                    <input
                      type="checkbox"
                      checked={rollbackSourceFenced03312}
                      onChange={(e) =>
                        setRollbackSourceFenced03312(e.target.checked)
                      }
                    />{" "}
                    Исходный процесс записи Gravit остаётся независимо остановленным
                  </label>
                  <button
                    disabled={
                      busy ||
                      cutoverConfirm03311 !== runId ||
                      !rollbackNeverFenced03312 ||
                      !/^[a-f0-9]{64}$/.test(rollbackHash03312)
                    }
                    onClick={() => void rollbackAction03312("plan", route)}
                  >
                    План: сверить изменения с MIG10
                  </button>
                  <button
                    disabled={
                      busy ||
                      !rollbackPlan03312?.ready ||
                      rollbackPlan03312.routeRevision !== route.revision ||
                      !rollbackSourceFenced03312 ||
                      !rollbackNeverFenced03312
                    }
                    onClick={() => void rollbackAction03312("commit", route)}
                  >
                    Подтвердить: восстановить прежний указатель канала Never (многофакторная проверка)
                  </button>
                  {rollbackPlan03312 &&
                    rollbackPlan03312.profileId === route.profileId &&
                    rollbackPlan03312.channel === route.channel && (
                      <p>
                        План: {statusRu(rollbackPlan03312.state)} (
                        {statusRu(rollbackPlan03312.mode)}),{" "}
                        {rollbackPlan03312.ready
                          ? "сверка пройдена"
                          : "ЗАБЛОКИРОВАНО"}
                        ; SHA-256: <code>{rollbackPlan03312.planSha256}</code>;
                        причины:{" "}
                        {rollbackPlan03312.blockers.join("; ") || "нет"}
                      </p>
                    )}
                </div>
              )}
              {route.state === "rolled_back" && (
                <p>
                  Указатель канала Never восстановлен. Gravit не перезапущен; проверьте
                  состояние игроков и завершите внешнее переключение отдельно.
                </p>
              )}
            </div>
          ))}
        </article>
      )}
      {run && (
        <article className="subcard">
          <h3>Отчёты и сертификация RC · MIG13</h3>
          <p>
            Отчёт формируется из реальных подтверждений этапов MIG03–MIG12.
            Состояние blocked запрещает утверждение; review_required означает
            необходимость независимой проверки, а не сертификацию промышленного выпуска.
          </p>
          <button
            disabled={busy}
            onClick={() => void reportAction03313("generate")}
          >
            Сформировать проверяемый отчёт
          </button>
          <button
            disabled={busy}
            onClick={() => void reportAction03313("status")}
          >
            Прочитать зафиксированный предрелизный отчёт
          </button>
          {report03313 && (
            <>
              <p>
                Статус: <strong>{statusRu(report03313.status)}</strong> · SHA-256:{" "}
                <code>{report03313.reportSha256}</code>
              </p>
              <p>
                Перенесено {report03313.counts.transferred}, преобразовано{" "}
                {report03313.counts.transformed}, вручную{" "}
                {report03313.counts.manual}, заблокировано{" "}
                {report03313.counts.blocked}. UUID:{" "}
                {report03313.identities.length}, решений:{" "}
                {report03313.operatorDecisions.length}.
              </p>
              {report03313.blockers.map((x, i) => (
                <p key={i} className="error">
                  {x}
                </p>
              ))}
              <button onClick={downloadReport03313}>
                Сохранить JSON-отчёт
              </button>
              <details>
                <summary>Доказательства и контрольные суммы</summary>
                <pre>{JSON.stringify(report03313.evidence, null, 2)}</pre>
              </details>
              <details>
                <summary>
                  Перенесено, преобразовано, вручную, заблокировано
                </summary>
                <pre>{JSON.stringify(report03313.items, null, 2)}</pre>
              </details>
              <details>
                <summary>ID источника → UUID → ID пользователя Never</summary>
                <pre>{JSON.stringify(report03313.identities, null, 2)}</pre>
              </details>
              <label className="field">
                <span>Ссылка на независимые CI/E2E доказательства</span>
                <input
                  value={reportRef03313}
                  onChange={(e) => setReportRef03313(e.target.value)}
                />
              </label>
              <label className="field">
                <span>SHA-256 доказательств</span>
                <input
                  value={reportEvidence03313}
                  onChange={(e) => setReportEvidence03313(e.target.value)}
                />
              </label>
              <label className="field">
                <span>Подтвердите точный ID запуска (многофакторная проверка)</span>
                <input
                  value={reportConfirm03313}
                  onChange={(e) => setReportConfirm03313(e.target.value)}
                />
              </label>
              <button
                disabled={
                  busy ||
                  report03313.status !== "review_required" ||
                  report03313.blockers.length > 0 ||
                  reportConfirm03313 !== runId ||
                  !/^[a-f0-9]{64}$/.test(reportEvidence03313) ||
                  reportRef03313.length < 8
                }
                onClick={() => void reportAction03313("review")}
              >
                Зафиксировать неизменяемый предрелизный отчёт (не GA-сертификация)
              </button>
            </>
          )}
          {review03313 && (
            <p>
              Зафиксировано: {statusRu(review03313.status)} · {review03313.reviewedBy} ·{" "}
              {review03313.reviewedAt} · SHA-256 отчёта:{" "}
              <code>{review03313.report.reportSha256}</code>.
            </p>
          )}
        </article>
      )}
      {compatibility && (
        <article className="subcard">
          <h3>Совместимость: {statusRu(compatibility.status)}</h3>
          <p>
            Версия:{" "}
            {compatibility.detectedVersion ??
              compatibility.claimedVersion ??
              "не определена"}{" "}
            ({statusRu(compatibility.versionStatus)}, {compatibility.versionEvidence});
            файлов: {compatibility.sourceEntries}. Переключение запрещено.
          </p>
          <p>
            SHA-256 архива: <code>{compatibility.sourceSha256}</code>
          </p>
          {compatibility.filesSha256 && (
            <p>SHA-256 инвентаря файлов: <code>{compatibility.filesSha256}</code></p>
          )}
          {compatibility.serverJarSha256 && (
            <p>SHA-256 файла LaunchServer.jar: <code>{compatibility.serverJarSha256}</code> (требует внешнего подтверждения происхождения)</p>
          )}
          {compatibility.categories && (
            <p>Разделы: {Object.entries(compatibility.categories).map(([name, count]) => `${name}: ${count}`).join("; ")}. Наличие файла не означает успешный перенос.</p>
          )}
          <ul>
            {compatibility.findings.map((finding, i) => (
              <li key={i}>
                <strong>{statusRu(finding.severity)}</strong> · {finding.code} ·{" "}
                {finding.component} {finding.path} — {finding.message}
              </li>
            ))}
          </ul>
          <details>
            <summary>Классификация файлов</summary>
            <pre>{JSON.stringify(compatibility.components, null, 2)}</pre>
          </details>
        </article>
      )}
      {run && (
        <article className="subcard" role="status">
          <p>
            <strong>Статус:</strong> {statusRu(run.status)} ·{" "}
            <strong>Текущий шаг:</strong> <code>{run.step}</code> ·{" "}
            <strong>Редакция:</strong> {run.revision} · <strong>Барьер:</strong>{" "}
            {run.fence}
          </p>
          {run.lastError && <p className="error">{run.lastError}</p>}
          <details>
            <summary>Зафиксированные результаты</summary>
            <pre>{JSON.stringify(run.result, null, 2)}</pre>
          </details>
          <details open>
            <summary>Журнал ({events.length})</summary>
            <pre>{JSON.stringify(events, null, 2)}</pre>
          </details>
        </article>
      )}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
    </section>
  );
}
