import { test } from "node:test";
import assert from "node:assert/strict";
import { validProviderPolicy02611 } from "../src/admin/official-provider-model-02611.ts";
import { canSeeSection } from "../src/admin/permissions.ts";
import { endpointForSection } from "../src/admin/sections.ts";
import { requestJSON, ApiError } from "../src/api/client.ts";
const id = "11223344-5566-7788-99aa-bbccddeeff00";
const basic = {
  clientId: id,
  enabled: true,
  browserEnabled: true,
  deviceEnabled: true,
  issuer: "consumers",
};
test("Проверяются публичный ID клиента, персональный издатель и хотя бы один разрешённый поток", () => {
  assert.equal(validProviderPolicy02611(basic), true);
  assert.equal(validProviderPolicy02611({ ...basic, clientId: "123" }), false);
  assert.equal(validProviderPolicy02611({ ...basic, issuer: "common" }), false);
  assert.equal(
    validProviderPolicy02611({
      ...basic,
      browserEnabled: false,
      deviceEnabled: false,
    }),
    false,
  );
  assert.equal(
    validProviderPolicy02611({
      ...basic,
      enabled: false,
      browserEnabled: false,
      deviceEnabled: false,
    }),
    true,
  );
  assert.equal(
    validProviderPolicy02611({
      ...basic,
      clientId: "00000000-0000-0000-0000-000000000000",
    }),
    false,
  );
});
test("Экран провайдера доступен только администраторам настроек", () => {
  const manager = {
    user: { id: "admin", email: "a@b.test", roleId: "admin" },
    permissions: ["settings:manage"],
    projectPermissions: {},
  };
  const viewer = {
    user: { id: "viewer", email: "v@b.test", roleId: "viewer" },
    permissions: [],
    projectPermissions: { project: ["project:read"] },
  };
  assert.equal(canSeeSection(manager, "official-provider", "project"), true);
  assert.equal(canSeeSection(viewer, "official-provider", "project"), false);
  assert.equal(
    endpointForSection("official-provider", "project"),
    "/api/v1/admin/official-provider",
  );
});
test("Обновление провайдера требует авторизации и не перезаписывает ревизию CAS незаметно", async () => {
  const orig = globalThis.fetch;
  try {
    globalThis.fetch = async (url, init) => {
      assert.equal(url, "https://example/api/v1/admin/official-provider");
      assert.equal(init.headers.get("Authorization"), "Bearer admin-secret");
      assert.equal(init.method, "PUT");
      assert.deepEqual(JSON.parse(init.body), {
        expectedRevision: 2,
        settings: basic,
        reason: "rotate app registration",
      });
      return {
        ok: false,
        status: 409,
        statusText: "Conflict",
        json: async () => ({
          error: { message: "provider revision conflict", code: 409 },
        }),
      };
    };
    await assert.rejects(
      requestJSON(
        "https://example",
        "/api/v1/admin/official-provider",
        "admin-secret",
        {
          method: "PUT",
          body: JSON.stringify({
            expectedRevision: 2,
            settings: basic,
            reason: "rotate app registration",
          }),
        },
      ),
      (e) => e instanceof ApiError && e.status === 409,
    );
  } finally {
    globalThis.fetch = orig;
  }
});
