import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ServerBridgeClient,
  gameCommandPermissions,
  commandLifecycle,
  telemetryState,
  canControlNode,
  supportsControlCapability,
  buildControlPayload,
  networkStateFresh,
  parseCapacityDraft,
  capacityApplied04111,
} from "../src/api/serverbridge.ts";
import { canSeeSection, can } from "../src/admin/permissions.ts";
import { endpointForSection } from "../src/admin/sections.ts";

const now = Date.now();
const node = {
  id: "paper-one",
  projectId: "one",
  status: "active",
  fresh: true,
  protocolVersion: 3,
  runtimeEpoch: 12,
  runtimeId: "a".repeat(64),
  lastHeartbeatAt: new Date(now - 1000).toISOString(),
  telemetry: {
    sampledAtUnixMillis: now - 2000,
    runtimeId: "a".repeat(64),
    runtimeEpoch: 12,
    playersOnline: 17,
    playersMax: 40,
  },
};

test("Обзорный маршрут и права проекта не дают глобальный доступ", () => {
  assert.equal(
    endpointForSection("server-bridge", "a/b"),
    "/api/v1/server-bridge/projects/a%2Fb/overview",
  );
  const actor = {
    user: { id: "one", email: "a", roleId: "player" },
    permissions: [],
    projectPermissions: {
      one: ["project:read", "serverbridge:control"],
      other: [],
    },
  };
  assert.equal(canSeeSection(actor, "server-bridge", "one"), true);
  assert.equal(canSeeSection(actor, "server-bridge", "other"), false);
  assert.equal(can(actor, "serverbridge:control", "one"), true);
  assert.equal(can(actor, "serverbridge:console", "one"), false);
});

test("Жизненный цикл управления различает отправку, доставку и исполнение", () => {
  assert.deepEqual(
    [
      "pending",
      "leased",
      "delivered",
      "accepted",
      "executed",
      "succeeded",
      "failed",
      "indeterminate",
    ].map((x) => commandLifecycle(x).lifecycle),
    [
      "queued",
      "dispatched",
      "delivered",
      "accepted",
      "executed",
      "verified",
      "failed",
      "indeterminate",
    ],
  );
  assert.equal(commandLifecycle("leased").deliveryConfirmed, false);
  assert.equal(commandLifecycle("succeeded").terminal, true);
  assert.equal(commandLifecycle("accepted").terminal, true);
  assert.equal(commandLifecycle("executed").terminal, true);
  assert.match(commandLifecycle("accepted").label, /не подтверждён/);
  assert.match(commandLifecycle("succeeded").label, /проверен/);
  assert.equal(commandLifecycle("expired").terminal, true);
  assert.equal(commandLifecycle("indeterminate").deliveryConfirmed, false);
  assert.equal(commandLifecycle("unknown").terminal, false);
});

test("Телеметрия скрывается для неизвестных, устаревших или ошибочных данных Runtime", () => {
  assert.equal(telemetryState(node, now).state, "fresh");
  assert.equal(
    telemetryState({ ...node, telemetry: undefined }, now).state,
    "unknown",
  );
  assert.equal(
    telemetryState(
      { ...node, telemetry: { ...node.telemetry, runtimeEpoch: 5 } },
      now,
    ).state,
    "stale",
  );
  assert.equal(telemetryState(node, now + 200_000).state, "stale");
  assert.equal(canControlNode(node, now), true);
  assert.equal(canControlNode({ ...node, protocolVersion: 2 }, now), false);
  assert.equal(
    canControlNode(
      { ...node, lastHeartbeatAt: new Date(now - 200_000).toISOString() },
      now,
    ),
    false,
  );
});

test("Версия 0.41.9 ошибочно показывает отсутствующий процесс или устаревший хост и игроков как исправных", () => {
  const process = 4711;
  const good = {
    ...node,
    runtimeProcessId: process,
    telemetryState: "fresh",
    telemetry: {
      ...node.telemetry,
      processId: process,
      processCpuLoad: 0.17,
      hostTotalMemoryBytes: 8589934592,
      hostFreeMemoryBytes: 4294967296,
    },
  };
  assert.equal(telemetryState(good, now).state, "fresh");
  assert.equal(
    telemetryState(
      { ...good, telemetryState: "stale", telemetry: undefined },
      now,
    ).state,
    "stale",
  );
  assert.equal(
    telemetryState(
      { ...good, telemetry: { ...good.telemetry, processId: 99 } },
      now,
    ).state,
    "stale",
  );
  assert.equal(
    telemetryState(
      { ...good, lastHeartbeatAt: new Date(now - 93_000).toISOString() },
      now,
    ).state,
    "stale",
  );
  assert.equal(
    telemetryState(
      {
        ...good,
        telemetry: { ...good.telemetry, sampledAtUnixMillis: now + 60_000 },
      },
      now,
    ).state,
    "unknown",
  );
  assert.equal(
    telemetryState({ ...good, status: "disabled" }, now).state,
    "stale",
  );
});

test("Форма формирует только разрешённые поля без shell-команд и неизвестных параметров", () => {
  const form = {
    username: "Notch",
    reason: "Reason",
    message: "Hello",
    enabled: true,
    command: "say Hello",
  };
  assert.deepEqual(buildControlPayload("player.kick", form), {
    username: "Notch",
    reason: "Reason",
  });
  assert.deepEqual(buildControlPayload("server.drain", form), {
    enabled: "true",
    reason: "Reason",
  });
  assert.deepEqual(buildControlPayload("server.save", form), {});
  assert.deepEqual(buildControlPayload("message.broadcast", form), {
    message: "Hello",
  });
  assert.throws(() =>
    buildControlPayload("server.console", { ...form, command: "op Notch" }),
  );
  assert.throws(() =>
    buildControlPayload("player.kick", { ...form, username: "invalid player" }),
  );
});

test("Реальный API использует endpoint команд, обзор области и неизменный ключ идемпотентности при повторе", async () => {
  const previous = globalThis.fetch;
  const calls = [];
  try {
    globalThis.fetch = async (url, options) => {
      calls.push({ url, options });
      return {
        ok: true,
        json: async () => ({
          data: url.endsWith("/overview")
            ? { nodes: [], control: [] }
            : url.endsWith("/control")
              ? {
                  status: "pending",
                  command: { id: "cmd-1", serverId: "node", status: "pending" },
                  idempotentReplay: false,
                }
              : {
                  command: {
                    id: "cmd-1",
                    serverId: "node",
                    status: "succeeded",
                  },
                },
        }),
      };
    };
    const client = new ServerBridgeClient("https://api.test", "secret");
    await client.overview("a/b");
    const cmd = {
      serverId: "node",
      type: "server.save",
      payload: {},
      idempotencyKey: "idempotency-fixed",
    };
    await client.send(cmd);
    await client.send(cmd);
    const result = await client.command("node", "cmd-1");
    assert.equal(result.status, "succeeded");
    assert.equal(
      calls[0].url,
      "https://api.test/api/v1/server-bridge/projects/a%2Fb/overview",
    );
    assert.equal(
      calls[1].url,
      "https://api.test/api/v1/server-bridge/servers/node/control",
    );
    assert.equal(
      calls[1].options.headers.get("Authorization"),
      "Bearer secret",
    );
    assert.equal(
      calls[1].options.headers.get("Idempotency-Key"),
      "idempotency-fixed",
    );
    assert.equal(
      calls[2].options.headers.get("Idempotency-Key"),
      "idempotency-fixed",
    );
    assert.equal(
      calls[3].url,
      "https://api.test/api/v1/server-bridge/servers/node/control/cmd-1",
    );
  } finally {
    globalThis.fetch = previous;
  }
});

test("0.28.1: разрешения доменов управления независимы и запрещают действия при неопределённости", () => {
  const actor = {
    user: { id: "broadcaster", roleId: "player" },
    permissions: [],
    projectPermissions: { one: ["project:read", "gameserver:broadcast"] },
  };
  assert.equal(
    can(actor, gameCommandPermissions["message.broadcast"], "one"),
    true,
  );
  for (const type of Object.keys(gameCommandPermissions).filter(
    (t) => t !== "message.broadcast",
  )) {
    assert.equal(
      can(actor, gameCommandPermissions[type], "one"),
      false,
      `${type} escalated from broadcast`,
    );
  }
  assert.equal(can(actor, "backend:control", "one"), false);
  assert.equal(can(actor, "host:process", "one"), false);
  assert.equal(can(actor, "host:exec", "one"), false);
  assert.equal(can(actor, "gameserver:broadcast", "other"), false);
  assert.equal(can(actor, "serverbridge:control", "one"), false);
  assert.equal(Object.keys(gameCommandPermissions).length, 13);
});

test("Групповое разрешение роли проекта не открывает управление хостом или Backend", () => {
  const role = {
    user: { id: "u", roleId: "player" },
    permissions: [],
    projectPermissions: { p: ["*"] },
  };
  assert.equal(can(role, "gameserver:broadcast", "p"), true);
  assert.equal(can(role, "backend:control", "p"), false);
  assert.equal(can(role, "host:process", "p"), false);
  assert.equal(can(role, "host:exec", "p"), false);
});

test("Версия 0.28.6 проверяет актуальность подписанного Runtime при фильтрации возможностей и безопасно отклоняет нарушения", () => {
  const reported = {
    ...node,
    kind: "sponge",
    runtimeLastSeenAt: new Date(now - 1000).toISOString(),
    runtimeCapabilities: ["adapter.control.broadcast", "adapter.control.kick"],
  };
  assert.equal(
    supportsControlCapability(reported, "message.broadcast", now),
    true,
  );
  assert.equal(supportsControlCapability(reported, "server.save", now), false);
  assert.equal(
    supportsControlCapability(reported, "server.console", now),
    false,
  );
  assert.equal(
    supportsControlCapability(
      { ...reported, runtimeCapabilities: undefined },
      "message.broadcast",
      now,
    ),
    false,
  );
  assert.equal(
    supportsControlCapability(
      { ...reported, runtimeLastSeenAt: new Date(now - 100_000).toISOString() },
      "message.broadcast",
      now,
    ),
    false,
  );
  assert.equal(
    supportsControlCapability(
      { ...reported, protocolVersion: 2 },
      "message.broadcast",
      now,
    ),
    false,
  );
});

test("0.28.8: актуальность подписанной маршрутизации не зависит от обзора в браузере", () => {
  const state = {
    nodeId: "paper-one",
    runtimeId: "a".repeat(64),
    runtimeEpoch: 12,
    routingRevision: 8,
    observedAt: new Date(now - 5000).toISOString(),
    lastHeartbeatAt: new Date(now - 4000).toISOString(),
  };
  assert.equal(networkStateFresh(state, now), true);
  assert.equal(networkStateFresh({ ...state, routingRevision: 0 }, now), false);
  assert.equal(
    networkStateFresh(
      { ...state, observedAt: new Date(now - 100000).toISOString() },
      now,
    ),
    false,
  );
  assert.equal(networkStateFresh({ ...state, runtimeId: "b" }, now), false);
  assert.equal(networkStateFresh({ ...state, runtimeEpoch: 0 }, now), false);
});
test("Версия 0.28.8 различает снятие ограничения, запрет и значения лимита в политике вместимости", () => {
  assert.equal(parseCapacityDraft(""), null);
  assert.equal(parseCapacityDraft("0"), 0);
  assert.equal(parseCapacityDraft("1000000"), 1000000);
  for (const value of ["-1", "1.5", "1e3", "001", "1000001", "Infinity"])
    assert.throws(() => parseCapacityDraft(value));
});
test("0.28.8: обновление ёмкости требует точный Runtime и оптимистическую ревизию", async () => {
  const previous = globalThis.fetch;
  let captured;
  try {
    globalThis.fetch = async (url, opts) => {
      captured = { url, opts };
      return {
        ok: true,
        json: async () => ({
          data: {
            nodeId: "paper-one",
            operatorCapacityMax: 0,
            operatorCapacityRevision: 6,
            status: "applied",
          },
        }),
      };
    };
    const client = new ServerBridgeClient("https://api.test", "token");
    const state = {
      runtimeId: "a".repeat(64),
      runtimeEpoch: 12,
      operatorCapacityRevision: 5,
    };
    const result = await client.setCapacity("paper-one", state, 0);
    assert.equal(result.operatorCapacityRevision, 6);
    assert.equal(captured.opts.method, "PUT");
    assert.equal(
      captured.url,
      "https://api.test/api/v1/server-bridge/servers/paper-one/network-capacity",
    );
    assert.deepEqual(JSON.parse(captured.opts.body), {
      capacityLimit: 0,
      runtimeId: state.runtimeId,
      runtimeEpoch: 12,
      expectedRevision: 5,
    });
  } finally {
    globalThis.fetch = previous;
  }
});

test("Версия 0.41.11 требует ответа Backend И независимого чтения PostgreSQL при допуске", () => {
  const receipt = {
    nodeId: "paper",
    operatorCapacityMax: 0,
    operatorCapacityRevision: 8,
  };
  const overview = {
    network: [
      { nodeId: "paper", operatorCapacityMax: 0, operatorCapacityRevision: 8 },
    ],
  };
  assert.equal(capacityApplied04111("paper", 7, 0, receipt, overview), true);
  assert.equal(capacityApplied04111("other", 7, 0, receipt, overview), false);
  assert.equal(capacityApplied04111("paper", 8, 0, receipt, overview), false);
  assert.equal(capacityApplied04111("paper", 7, 20, receipt, overview), false);
  assert.equal(
    capacityApplied04111(
      "paper",
      7,
      0,
      { ...receipt, operatorCapacityRevision: 0 },
      overview,
    ),
    false,
  );
  assert.equal(
    capacityApplied04111("paper", 7, 0, receipt, { network: [] }),
    false,
  );
  assert.equal(
    capacityApplied04111("paper", 7, 0, receipt, {
      network: [{ ...overview.network[0], operatorCapacityMax: 1 }],
    }),
    false,
  );
});
