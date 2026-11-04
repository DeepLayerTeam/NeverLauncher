import { test } from "node:test";
import assert from "node:assert/strict";
import {
  HostOperationsClient04111,
  validHostPending04111,
  hostOperationOutcome04111,
  hostSnapshotFresh04111,
  bridgeReady04111,
} from "../src/api/host-operations-04111.ts";
import { can } from "../src/admin/permissions.ts";

const now = Date.now();
const id = "a".repeat(64);
const live = {
  observedAt: new Date(now - 1000).toISOString(),
  host: {
    nodeId: "remote-1",
    status: {
      configured: true,
      observedStatus: "running",
      processAlive: true,
      supervisorAlive: true,
      sessionId: "session-1",
      telemetry: { processId: 101 },
    },
  },
  bridge: {
    serverId: "paper-1",
    status: "active",
    runtimeId: id,
    runtimeEpoch: 2,
    lastHeartbeatAt: new Date(now - 3000).toISOString(),
  },
};

test("host permissions cannot be inherited from project game-scopes", () => {
  const scoped = {
    user: { id: "operator", roleId: "user" },
    permissions: [],
    projectPermissions: { one: ["*", "gameserver:shutdown", "host:process"] },
  };
  assert.equal(can(scoped, "host:process", "one"), false);
  assert.equal(can(scoped, "gameserver:shutdown", "one"), true);
  assert.equal(
    can({ ...scoped, permissions: ["host:process"] }, "host:process"),
    true,
  );
});
test("snapshot freshness declares disconnected host or stale bridge healthy", () => {
  assert.equal(hostSnapshotFresh04111(live, now), true);
  assert.equal(bridgeReady04111(live, now), true);
  assert.equal(
    hostSnapshotFresh04111(
      { ...live, observedAt: new Date(now - 30000).toISOString() },
      now,
    ),
    false,
  );
  assert.equal(
    hostSnapshotFresh04111(
      {
        ...live,
        host: {
          ...live.host,
          status: { ...live.host.status, configured: false },
        },
      },
      now,
    ),
    false,
  );
  assert.equal(
    bridgeReady04111(
      {
        ...live,
        bridge: {
          ...live.bridge,
          lastHeartbeatAt: new Date(now - 100000).toISOString(),
        },
      },
      now,
    ),
    false,
  );
  assert.equal(
    bridgeReady04111(
      { ...live, bridge: { ...live.bridge, runtimeEpoch: 0 } },
      now,
    ),
    false,
  );
  assert.equal(bridgeReady04111(null, now), false);
});
test("indeterminate and accepted are verified outcomes", () => {
  for (const status of ["accepted", "indeterminate"]) {
    const result = hostOperationOutcome04111({ status });
    assert.equal(result.verified, false);
    assert.equal(result.unresolved, true);
  }
  assert.equal(
    hostOperationOutcome04111({ status: "succeeded" }).verified,
    true,
  );
});
test("restore input allows only complete, original command identity", () => {
  const valid = {
    serverId: "paper-1",
    action: "restart",
    idempotencyKey: "reboot-key-000000000001",
  };
  assert.equal(validHostPending04111(valid), true);
  assert.equal(validHostPending04111({ ...valid, action: "exec" }), false);
  assert.equal(validHostPending04111({ ...valid, idempotencyKey: "x" }), false);
  assert.equal(validHostPending04111({ ...valid, serverId: "../api" }), false);
  assert.equal(validHostPending04111({}), false);
});
test("real HTTP calls list PostgreSQL journal, check RemoteControl and reissue action on GET", async () => {
  const old = globalThis.fetch;
  const requests = [];
  try {
    globalThis.fetch = async (url, init) => {
      requests.push({ url, init });
      const data = url.includes("/host/status")
        ? live
        : url.endsWith("/host/operations") && init.method !== "POST"
          ? { items: [{ id: "op-1", status: "accepted", action: "restart" }] }
          : url.includes("/host/operations/op-1")
            ? {
                operation: { id: "op-1", status: "succeeded" },
                hostState: "succeeded",
              }
            : {
                operation: {
                  id: "op-1",
                  status: "accepted",
                  serverId: "paper-1",
                  action: "restart",
                  idempotencyKey: "reboot-key-000000000001",
                },
                idempotentReplay: true,
              };
      return { ok: true, status: 200, json: async () => ({ data }) };
    };
    const api = new HostOperationsClient04111(
      "https://example.invalid/",
      "token",
    );
    await api.status("paper-1");
    const list = await api.list("paper-1");
    assert.equal(list.length, 1);
    const saved = {
      serverId: "paper-1",
      action: "restart",
      idempotencyKey: "reboot-key-000000000001",
    };
    const x = await api.create(saved);
    const y = await api.create(saved);
    assert.equal(x.operation.id, y.operation.id);
    await api.get("paper-1", "op-1", true);
    assert.equal(requests.length, 5);
    assert.deepEqual(
      requests.map((r) => r.init.method ?? "GET"),
      ["GET", "GET", "POST", "POST", "GET"],
    );
    assert.equal(
      requests[2].init.headers.get("Idempotency-Key"),
      saved.idempotencyKey,
    );
    assert.equal(
      requests[3].init.headers.get("Idempotency-Key"),
      saved.idempotencyKey,
    );
    assert.equal(
      requests[4].url,
      "https://example.invalid/api/v1/server-bridge/servers/paper-1/host/operations/op-1?refresh=1",
    );
    assert.equal(requests[2].init.headers.get("Authorization"), "Bearer token");
    assert.equal(requests[3].init.body, JSON.stringify({ action: "restart" }));
  } finally {
    globalThis.fetch = old;
  }
});
