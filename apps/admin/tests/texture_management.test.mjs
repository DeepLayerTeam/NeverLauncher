import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { requestJSON, ApiError } from "../src/api/client.ts";
import { canSeeSection } from "../src/admin/permissions.ts";
import { routeIds } from "../src/admin/route-links-0381.ts";

test("Admin textures are hidden from operators without global settings:manage", () => {
  assert.ok(routeIds.includes("texture-management"));
  const operator = {
    permissions: [],
    projectPermissions: { demo: ["project:read", "project:write"] },
  };
  assert.equal(canSeeSection(operator, "texture-management", "demo"), false);
  assert.equal(
    canSeeSection(
      { ...operator, permissions: ["settings:manage"] },
      "texture-management",
      "demo",
    ),
    true,
  );
});

test("Policy CAS and individual decisions preserve payload, MFA token and project scope", async () => {
  const calls = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      calls.push({
        url: req.url,
        method: req.method,
        auth: req.headers.authorization,
        body: body ? JSON.parse(body) : null,
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          data:
            req.method === "PUT"
              ? { status: "saved" }
              : { revision: 2, allowPlayerSkins: true },
        }),
      );
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    await requestJSON(
      base,
      "/api/v1/admin/textures/policy?projectId=",
      "token",
      {
        method: "PUT",
        body: JSON.stringify({
          expectedRevision: 1,
          policy: { defaultSkinModel: "slim" },
          reason: "admin override",
        }),
      },
    );
    await requestJSON(
      base,
      "/api/v1/admin/textures/exceptions/alice?projectId=demo",
      "token",
      {
        method: "PUT",
        body: JSON.stringify({
          kind: "cape",
          decision: "deny",
          reason: "moderation",
        }),
      },
    );
    assert.equal(calls.length, 2);
    assert.deepEqual(
      calls.map((c) => c.method),
      ["PUT", "PUT"],
    );
    assert.ok(calls.every((c) => c.auth === "Bearer token"));
    assert.equal(calls[0].body.expectedRevision, 1);
    assert.equal(calls[0].body.policy.defaultSkinModel, "slim");
    assert.equal(calls[1].body.decision, "deny");
    assert.equal(
      calls[1].url,
      "/api/v1/admin/textures/exceptions/alice?projectId=demo",
    );
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Policy conflict is exposed to Admin, silently replayed", async () => {
  const server = createServer((req, res) => {
    res.writeHead(409, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        error: { message: "revision changed", reasonCode: "revision_conflict" },
      }),
    );
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    await assert.rejects(
      () =>
        requestJSON(base, "/api/v1/admin/textures/policy", "token", {
          method: "PUT",
          body: "{}",
        }),
      (e) => e instanceof ApiError && e.status === 409,
    );
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
