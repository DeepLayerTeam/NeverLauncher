import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import {
  requestJSON,
  ApiError,
  IndeterminateApiError,
} from "../src/api/client.ts";
import { can, canSeeSection } from "../src/admin/permissions.ts";

// Real loopback TCP server: lost replies are exercised over an actual socket,
// not a mocked fetch implementation.
async function withBackend(handler, run) {
  const server = createServer(handler);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    await run(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve())),
    );
  }
}

test("lost POST response is indeterminate, automatically replayed", async () => {
  const effects = new Set();
  let calls = 0;
  await withBackend(
    (req, res) => {
      calls++;
      const key = req.headers["idempotency-key"];
      assert.equal(req.method, "POST");
      if (key) effects.add(key);
      if (calls === 1) {
        req.socket.destroy();
        return;
      }
      res.writeHead(202, { "content-type": "application/json" });
      res.end(
        JSON.stringify({ data: { id: "durable-job-1", status: "pending" } }),
      );
    },
    async (base) => {
      const init = {
        method: "POST",
        headers: { "Idempotency-Key": "release-unique-request" },
        body: JSON.stringify({ kind: "channel-rollback" }),
      };
      await assert.rejects(
        () => requestJSON(base, "/api/v1/operations/execute", "token", init),
        (e) =>
          e instanceof IndeterminateApiError &&
          /idempotency key/.test(e.message),
      );
      assert.equal(calls, 1, "client silently retried an unknown mutation");
      const result = await requestJSON(
        base,
        "/api/v1/operations/execute",
        "token",
        init,
      );
      assert.equal(result.id, "durable-job-1");
      assert.equal(effects.size, 1);
    },
  );
});

test("structured 401, 403, 409 and 503 remain distinguishable", async () => {
  await withBackend(
    (req, res) => {
      const status = Number(req.url.slice(1));
      res.writeHead(status, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          error: {
            reasonCode:
              status === 409 ? "revision_conflict" : `error_${status}`,
            message: `Backend: ${status}`,
          },
        }),
      );
    },
    async (base) => {
      for (const code of [401, 403, 409, 503])
        await assert.rejects(
          () => requestJSON(base, `/${code}`, "session"),
          (e) =>
            e instanceof ApiError &&
            e.status === code &&
            e.message === `Backend: ${code}` &&
            e.reasonCode ===
              (code === 409 ? "revision_conflict" : `error_${code}`),
        );
    },
  );
});

test("broken successful JSON silently confirms a mutation", async () => {
  await withBackend(
    (req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<html>nginx</html>");
    },
    async (base) => {
      await assert.rejects(
        () =>
          requestJSON(base, "/api/v1/admin/config", "session", {
            method: "PUT",
            body: "{}",
          }),
        IndeterminateApiError,
      );
      await assert.rejects(
        () => requestJSON(base, "/api/v1/admin/config", "session"),
        (e) =>
          e instanceof ApiError && e.reasonCode === "invalid-backend-response",
      );
    },
  );
});

test("aborted GET is not confused with an unavailable Backend", async () => {
  const signal = new AbortController();
  signal.abort();
  await withBackend(
    (req, res) => res.end("{}"),
    async (base) => {
      await assert.rejects(
        () =>
          requestJSON(base, "/api/v1/admin/me", "session", {
            signal: signal.signal,
          }),
        (e) => e.name === "AbortError",
      );
    },
  );
});

test("RBAC display denies privileged screens to project-only operator", () => {
  const operator = {
    user: { id: "operator", roleId: "player" },
    permissions: [],
    projectPermissions: { alpha: ["project:read", "serverbridge:control"] },
  };
  assert.equal(canSeeSection(operator, "server-bridge", "alpha"), true);
  assert.equal(canSeeSection(operator, "server-bridge", "beta"), false);
  assert.equal(canSeeSection(operator, "config", "alpha"), false);
  assert.equal(canSeeSection(operator, "audit", "alpha"), false);
  assert.equal(canSeeSection(operator, "backup-restore", "alpha"), false);
  assert.equal(can(operator, "serverbridge:console", "alpha"), false);
  assert.equal(can(operator, "serverbridge:control", "beta"), false);
});
