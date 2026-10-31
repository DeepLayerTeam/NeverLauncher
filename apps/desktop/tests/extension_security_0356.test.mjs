import test from "node:test";
import assert from "node:assert/strict";
import {
  identity0356,
  validExtension0356,
  verifiedEntrypoint0356,
  validRPC0356,
  authorizedBridge0356,
} from "../build-tests/extension_security_0356.js";
const item = {
  extensionId: "example.desktop",
  version: "1.0.0",
  generation: 2,
  scope: "project",
  scopeId: "project-a",
  bridgeAllowed: true,
  desktop: { pages: [], actions: [] },
};
test("only selected project and valid scoped extensions may render", () => {
  assert.equal(validExtension0356(item, "project-a"), true);
  assert.equal(validExtension0356(item, "project-b"), false);
  assert.equal(
    validExtension0356(
      { ...item, scope: "global", scopeId: "project-a" },
      "project-a",
    ),
    false,
  );
  assert.equal(
    validExtension0356({ ...item, extensionId: "../bad" }, "project-a"),
    false,
  );
  assert.equal(
    validExtension0356({ ...item, generation: -1 }, "project-a"),
    false,
  );
});
test("HTML belongs to exact version, generation and extension", () => {
  const data = {
    protocol: "extensions.desktop-rpc.v1",
    extensionApiVersion: "1.0",
    extensionId: item.extensionId,
    version: item.version,
    generation: 2,
    html: "<h1>OK</h1>",
  };
  assert.equal(verifiedEntrypoint0356(data, item), data.html);
  for (const change of [
    { generation: 1 },
    { version: "2.0.0" },
    { extensionId: "evil.desktop" },
    { html: "x".repeat(2 * 1024 * 1024 + 1) },
  ]) {
    assert.throws(() => verifiedEntrypoint0356({ ...data, ...change }, item));
  }
  assert.notEqual(identity0356(item), identity0356({ ...item, generation: 3 }));
});
test("RPC fails closed for malformed method, envelope, size and identifiers", () => {
  const base = {
    protocol: "extensions.desktop-rpc.v1",
    type: "rpc.request",
    id: "rpc-1",
    method: "context.get",
    params: {},
  };
  assert.equal(validRPC0356(base), true);
  for (const change of [
    { id: "../etc" },
    { method: "__proto__" },
    { method: "tauri.open;sh" },
    { params: { contents: "x".repeat(65536) } },
    { protocol: "other" },
    { type: "host.context" },
  ]) {
    assert.equal(validRPC0356({ ...base, ...change }), false);
  }
});
test("bridge requires fresh affirmative Backend attestation for exact action and install", () => {
  const grant = {
    authorized: true,
    extensionId: item.extensionId,
    version: item.version,
    generation: item.generation,
    action: "tauri.openGameDirectory",
  };
  assert.equal(
    authorizedBridge0356(grant, item, "tauri.openGameDirectory"),
    true,
  );
  for (const change of [
    { authorized: false },
    { generation: 3 },
    { version: "9.0" },
    { action: "tauri.platform" },
    { extensionId: "other" },
  ]) {
    assert.equal(
      authorizedBridge0356(
        { ...grant, ...change },
        item,
        "tauri.openGameDirectory",
      ),
      false,
    );
  }
});
