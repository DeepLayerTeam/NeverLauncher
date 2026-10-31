import { test } from "node:test";
import assert from "node:assert/strict";
import { canSeeSection } from "../src/admin/permissions.ts";
import { endpointForSection } from "../src/admin/sections.ts";
import { requestJSON, ApiError } from "../src/api/client.ts";
const base = "/api/v1/admin/auth/provider-wizard";
const admin = {
  user: { id: "operator", email: "operator@example.test", roleId: "admin" },
  permissions: ["settings:manage"],
  projectPermissions: {},
};
const viewer = {
  user: { id: "viewer", email: "viewer@example.test", roleId: "viewer" },
  permissions: [],
  projectPermissions: {},
};
test("only settings managers can open Auth Provider Wizard", () => {
  assert.equal(canSeeSection(admin, "auth-provider-wizard", "default"), true);
  assert.equal(canSeeSection(viewer, "auth-provider-wizard", "default"), false);
  assert.equal(endpointForSection("auth-provider-wizard", "default"), base);
});
test("draft API requires authenticated request and does not include raw DSN in payload", async () => {
  const original = globalThis.fetch;
  try {
    globalThis.fetch = async (url, init) => {
      assert.equal(url, `https://example${base}/drafts`);
      assert.equal(init.headers.get("Authorization"), "Bearer operator-token");
      assert.equal(init.method, "POST");
      const data = JSON.parse(init.body);
      assert.equal(data.config.dsnEnv, "AUTH_SQL_DSN");
      assert.equal(JSON.stringify(data).includes("postgres://"), false);
      return {
        ok: true,
        status: 201,
        json: async () => ({ revision: 1, id: "sql-prod" }),
      };
    };
    const result = await requestJSON(
      "https://example",
      `${base}/drafts`,
      "operator-token",
      {
        method: "POST",
        body: JSON.stringify({
          id: "sql-prod",
          kind: "sql",
          config: { id: "sql-prod", dsnEnv: "AUTH_SQL_DSN" },
          reason: "release candidate",
        }),
      },
    );
    assert.equal(result.revision, 1);
  } finally {
    globalThis.fetch = original;
  }
});
test("conflicting activation retries silently", async () => {
  const original = globalThis.fetch;
  let calls = 0;
  try {
    globalThis.fetch = async (_url, init) => {
      calls++;
      assert.deepEqual(JSON.parse(init.body), {
        revision: 5,
        expectedActiveRevision: 4,
        reason: "switch issuer",
      });
      return {
        ok: false,
        status: 409,
        statusText: "Conflict",
        json: async () => ({ error: { message: "active revision changed" } }),
      };
    };
    await assert.rejects(
      requestJSON(
        "https://example",
        `${base}/sql-prod/activate`,
        "operator-token",
        {
          method: "POST",
          body: JSON.stringify({
            revision: 5,
            expectedActiveRevision: 4,
            reason: "switch issuer",
          }),
        },
      ),
      (error) => error instanceof ApiError && error.status === 409,
    );
    assert.equal(calls, 1);
  } finally {
    globalThis.fetch = original;
  }
});
