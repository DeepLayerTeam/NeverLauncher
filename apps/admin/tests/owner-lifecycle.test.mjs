import { test } from "node:test";
import assert from "node:assert/strict";
import { ReleaseApi } from "../src/api/release.ts";
import {
  recoveryStorageKey,
  readOwnerPending,
  saveOwnerPending,
  clearOwnerPending,
  prepareOwnerOperation,
  observeOwnerOperation,
} from "../src/admin/owner-lifecycle-03513.ts";

const intent = {
  kind: "package-publish",
  projectId: "owner",
  profileId: "fabric",
  channel: "stable",
  resourceId: "pkg-1",
  idempotencyKey: "unique-intent-1",
};
const before = {
  projectId: "owner",
  profileId: "fabric",
  channel: "stable",
  revision: 3,
  releaseId: "pkg-old",
  version: "1.0",
};
const after = { ...before, revision: 4, releaseId: "pkg-1", version: "2.0" };
const pending = { intent, before, jobId: "job-1" };
function fakeStore() {
  const map = new Map();
  return {
    getItem: (k) => map.get(k) ?? null,
    setItem: (k, v) => map.set(k, v),
    removeItem: (k) => map.delete(k),
    map,
  };
}
const json = (data) => ({
  ok: true,
  status: 200,
  json: async () => ({ apiVersion: "1", data }),
});
async function scripted(handlers, fn) {
  const old = globalThis.fetch;
  const visited = [];
  try {
    globalThis.fetch = async (url, options) => {
      const pathname = new URL(url).pathname;
      visited.push([pathname, options]);
      const handler = handlers[pathname];
      assert.ok(handler, `unexpected API request ${pathname}`);
      return json(typeof handler === "function" ? handler(options) : handler);
    };
    return await fn(visited);
  } finally {
    globalThis.fetch = old;
  }
}

test("recovery uses project, backend and session boundary; tokens stored", () => {
  const store = fakeStore();
  const a = recoveryStorageKey("https://api.example/", "owner", "s1");
  assert.notEqual(a, recoveryStorageKey("https://api.example", "owner", "s2"));
  assert.notEqual(
    a,
    recoveryStorageKey("https://other.example", "owner", "s1"),
  );
  saveOwnerPending(store, a, pending);
  assert.deepEqual(readOwnerPending(store, a, "owner"), pending);
  assert.equal(readOwnerPending(store, a, "other"), null);
  assert.doesNotMatch(store.getItem(a), /Bearer|token|password/i);
  clearOwnerPending(store, a);
  assert.equal(readOwnerPending(store, a, "owner"), null);
});
test("corrupt and foreign persistent intents fail closed", () => {
  const store = fakeStore();
  const key = "intent";
  for (const value of [
    "not-json",
    "{}",
    JSON.stringify({ ...pending, intent: { ...intent, projectId: "another" } }),
    JSON.stringify({ ...pending, before: { ...before, channel: "dev" } }),
    JSON.stringify({ ...pending, jobId: 123 }),
    JSON.stringify({ ...pending, intent: { ...intent, idempotencyKey: "" } }),
  ]) {
    store.setItem(key, value);
    assert.equal(readOwnerPending(store, key, "owner"), null);
  }
  assert.throws(
    () =>
      saveOwnerPending(store, key, {
        ...pending,
        before: { ...before, profileId: "forge" },
      }),
    /Недопустимый/,
  );
});
test("owner validates a real channel head and Backend preview before allowing execution", async () => {
  await scripted(
    {
      "/api/v1/projects/owner/profiles/fabric/channels/stable/head": before,
      "/api/v1/operations/validate": {
        valid: true,
        permission: "release:publish",
        effect: { packageId: "pkg-1" },
      },
    },
    async (visits) => {
      const result = await prepareOwnerOperation(
        new ReleaseApi("https://api.example", "token"),
        intent,
      );
      assert.deepEqual(result.before, before);
      assert.equal(result.preview.valid, true);
      assert.deepEqual(
        visits.map((x) => x[0]),
        [
          "/api/v1/projects/owner/profiles/fabric/channels/stable/head",
          "/api/v1/operations/validate",
        ],
      );
      assert.equal(visits[1][1].headers.get("Authorization"), "Bearer token");
      assert.equal(
        JSON.parse(visits[1][1].body).idempotencyKey,
        intent.idempotencyKey,
      );
    },
  );
});
test("rejects mismatched channel head, invalid input and invalid validation", async () => {
  await scripted(
    {
      "/api/v1/projects/owner/profiles/fabric/channels/stable/head": {
        ...before,
        profileId: "vanilla",
      },
    },
    async () => {
      await assert.rejects(
        prepareOwnerOperation(
          new ReleaseApi("https://api.example", "t"),
          intent,
        ),
        /привязку/,
      );
    },
  );
  await scripted(
    {
      "/api/v1/projects/owner/profiles/fabric/channels/stable/head": before,
      "/api/v1/operations/validate": { valid: false },
    },
    async () => {
      await assert.rejects(
        prepareOwnerOperation(
          new ReleaseApi("https://api.example", "t"),
          intent,
        ),
        /отклонил/,
      );
    },
  );
  await assert.rejects(
    prepareOwnerOperation(new ReleaseApi("https://api.example", "t"), {
      ...intent,
      projectId: "",
    }),
    /Некорректная/,
  );
});
test("pending/failed jobs cannot be presented as published", async () => {
  for (const [status, phase] of [
    ["pending", "waiting"],
    ["running", "waiting"],
    ["failed", "failed"],
    ["dead", "failed"],
    ["revoked", "failed"],
  ]) {
    await scripted(
      {
        "/api/v1/operations/job-1": {
          id: "job-1",
          projectId: "owner",
          kind: "package-publish",
          resourceId: "pkg-1",
          status,
        },
      },
      async () => {
        const result = await observeOwnerOperation(
          new ReleaseApi("https://api.example", "t"),
          pending,
        );
        assert.equal(result.phase, phase);
        assert.equal(result.head, undefined);
      },
    );
  }
});
test("successful publish requires the ACTUAL channel head at expected package", async () => {
  for (const [head, phase] of [
    [before, "unconfirmed"],
    [{ ...after, releaseId: "other-pkg" }, "unconfirmed"],
    [after, "confirmed"],
  ]) {
    await scripted(
      {
        "/api/v1/operations/job-1": {
          id: "job-1",
          projectId: "owner",
          kind: "package-publish",
          resourceId: "pkg-1",
          status: "succeeded",
          result: { status: "published", releaseId: "pkg-1" },
        },
        "/api/v1/projects/owner/profiles/fabric/channels/stable/head": head,
      },
      async () => {
        assert.equal(
          (
            await observeOwnerOperation(
              new ReleaseApi("https://api.example", "t"),
              pending,
            )
          ).phase,
          phase,
        );
      },
    );
  }
});
test("project or resource mismatch in durable job fails closed", async () => {
  for (const job of [
    {
      id: "job-1",
      projectId: "other",
      kind: "package-publish",
      resourceId: "pkg-1",
      status: "succeeded",
    },
    {
      id: "job-1",
      projectId: "owner",
      kind: "package-publish",
      resourceId: "pkg-2",
      status: "succeeded",
    },
  ]) {
    await scripted({ "/api/v1/operations/job-1": job }, async () =>
      assert.rejects(
        observeOwnerOperation(
          new ReleaseApi("https://api.example", "t"),
          pending,
        ),
        /не соответствует/,
      ),
    );
  }
});
test("rollback to stable is STAGED when real Backend requires trusted runtime evidence", async () => {
  const rollback = {
    intent: {
      ...intent,
      kind: "channel-rollback",
      toVersion: "1.0",
      resourceId: undefined,
    },
    before,
    jobId: "job-1",
  };
  await scripted(
    {
      "/api/v1/operations/job-1": {
        id: "job-1",
        projectId: "owner",
        kind: "channel-rollback",
        resourceId: "stable",
        status: "succeeded",
        result: {
          status: "rollback-staged-runtime-validation-required",
          packageId: "rollback-new",
        },
      },
    },
    async () => {
      const result = await observeOwnerOperation(
        new ReleaseApi("https://api.example", "t"),
        rollback,
      );
      assert.equal(result.phase, "staged");
      assert.match(result.message, /rollback-new/);
    },
  );
});
test("successful rollback requires exact newly published package from job result", async () => {
  const rollback = {
    intent: {
      ...intent,
      kind: "channel-rollback",
      toVersion: "1.0",
      resourceId: undefined,
    },
    before,
    jobId: "job-1",
  };
  for (const [releaseID, phase] of [
    ["other", "unconfirmed"],
    ["rollback-new", "confirmed"],
  ]) {
    await scripted(
      {
        "/api/v1/operations/job-1": {
          id: "job-1",
          projectId: "owner",
          kind: "channel-rollback",
          resourceId: "stable",
          status: "succeeded",
          result: {
            status: "rolled-back-as-new-validated-immutable-release",
            packageId: "rollback-new",
          },
        },
        "/api/v1/projects/owner/profiles/fabric/channels/stable/head": {
          ...after,
          releaseId: releaseID,
        },
      },
      async () => {
        assert.equal(
          (
            await observeOwnerOperation(
              new ReleaseApi("https://api.example", "t"),
              rollback,
            )
          ).phase,
          phase,
        );
      },
    );
  }
});
test("API retry reuses exact intent and authenticated endpoint", async () => {
  await scripted(
    {
      "/api/v1/operations/execute": {
        id: "job-original",
        projectId: "owner",
        kind: "package-publish",
        status: "pending",
        resourceId: "pkg-1",
      },
    },
    async (visits) => {
      const api = new ReleaseApi("https://api.example", "secret");
      assert.equal(
        (await api.executeOperation(pending.intent)).id,
        "job-original",
      );
      assert.equal(
        (await api.executeOperation(pending.intent)).id,
        "job-original",
      );
      assert.deepEqual(
        JSON.parse(visits[0][1].body),
        JSON.parse(visits[1][1].body),
      );
      assert.equal(visits[0][1].headers.get("Authorization"), "Bearer secret");
    },
  );
});

test("stable staged rollback resumes actual signed package in server-owned draft, a synthetic release", async () => {
  const { openStagedRollback } =
    await import("../src/admin/owner-lifecycle-03513.ts");
  const rollback = {
    intent: {
      ...intent,
      kind: "channel-rollback",
      toVersion: "1.0",
      resourceId: undefined,
    },
    before,
    jobId: "job-1",
  };
  const check = {
    phase: "staged",
    job: {
      id: "job-1",
      kind: "channel-rollback",
      result: { packageId: "rollback-staged" },
    },
  };
  await scripted(
    {
      "/api/v1/packages/rollback-staged": {
        packageId: "rollback-staged",
        projectId: "owner",
        profileId: "fabric",
        channel: "stable",
        status: "staged",
        version: "1.0-rollback-job-1",
        minecraft: { version: "1.21.1", loader: "fabric" },
      },
      "/api/v1/release-drafts": (opts) => ({
        id: "new-owner-draft",
        ...JSON.parse(opts.body),
        revision: 1,
      }),
    },
    async (visits) => {
      const result = await openStagedRollback(
        new ReleaseApi("https://api.example", "token"),
        rollback,
        check,
      );
      assert.equal(result.draft.id, "new-owner-draft");
      assert.equal(result.fields.packageId, "rollback-staged");
      assert.equal(result.fields.step, "verify");
      assert.deepEqual(
        visits.map((x) => x[0]),
        ["/api/v1/packages/rollback-staged", "/api/v1/release-drafts"],
      );
    },
  );
});
test("staged rollback refuses mismatched backend package without creating a draft", async () => {
  const { openStagedRollback } =
    await import("../src/admin/owner-lifecycle-03513.ts");
  const rollback = {
    intent: {
      ...intent,
      kind: "channel-rollback",
      toVersion: "1.0",
      resourceId: undefined,
    },
    before,
    jobId: "job-1",
  };
  const check = {
    phase: "staged",
    job: {
      id: "job-1",
      kind: "channel-rollback",
      result: { packageId: "rollback-staged" },
    },
  };
  await scripted(
    {
      "/api/v1/packages/rollback-staged": {
        packageId: "rollback-staged",
        projectId: "different",
        profileId: "fabric",
        channel: "stable",
        status: "staged",
        version: "1.0-rollback-job-1",
        minecraft: { version: "1.21.1", loader: "fabric" },
      },
    },
    async (visits) => {
      await assert.rejects(
        openStagedRollback(
          new ReleaseApi("https://api.example", "t"),
          rollback,
          check,
        ),
        /не соответствует/,
      );
      assert.equal(visits.length, 1);
    },
  );
  await assert.rejects(
    openStagedRollback(new ReleaseApi("https://api.example", "t"), rollback, {
      ...check,
      phase: "confirmed",
    }),
    /Нет подтверждённого/,
  );
});
