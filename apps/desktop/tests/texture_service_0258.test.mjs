import test from "node:test";
import assert from "node:assert/strict";
import {
  TextureServiceClient0258,
  TextureServiceError0258,
  textureRevision0258,
  textureAssignment0258,
  validateTextureFile0258,
  safeOfficialTextureURL0258,
} from "../build-tests/texture_service_0258.js";
const digest = "a".repeat(64);
function response(data, status = 200, headers = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers(headers),
    json: async () => data,
  };
}
function mockResponse(data, status = 200) {
  return response({ apiVersion: "0.25.8", data }, status);
}
test("safe Mojang textures only, upgrades legacy CDN http", () => {
  assert.equal(
    safeOfficialTextureURL0258(
      "http://textures.minecraft.net/texture/" + digest,
    ),
    "https://textures.minecraft.net/texture/" + digest,
  );
  assert.equal(
    safeOfficialTextureURL0258(
      "https://textures.minecraft.net/texture/" + digest,
    ),
    "https://textures.minecraft.net/texture/" + digest,
  );
  for (const value of [
    "https://localhost/texture/" + digest,
    "https://evil.example/?url=https://textures.minecraft.net/texture/" +
      digest,
    "https://textures.minecraft.net.evil.com/texture/" + digest,
    "http://127.0.0.1/texture/" + digest,
    "https://textures.minecraft.net:443/texture/" + digest + "?x=1",
    "javascript:alert(1)",
    "https://textures.minecraft.net/texture/../admin",
  ]) {
    assert.equal(safeOfficialTextureURL0258(value), undefined, value);
  }
});
test("revision selects local account scoped current state, not launcher profile", () => {
  const entries = [
    { kind: "skin", revision: 4, projectId: "project", blobDigest: "wrong" },
    { kind: "skin", revision: 7, projectId: "", blobDigest: digest },
    { kind: "cape", revision: 3, projectId: "" },
  ];
  assert.equal(textureRevision0258(entries, "skin"), 7);
  assert.equal(textureRevision0258(entries, "cape"), 3);
  assert.equal(textureAssignment0258(entries, "skin").blobDigest, digest);
  assert.equal(textureRevision0258([], "skin"), 0);
});
test("upload validates PNG size/type/name before network request", () => {
  assert.throws(() =>
    validateTextureFile0258({ name: "foo.txt", size: 4, type: "image/png" }),
  );
  assert.throws(() =>
    validateTextureFile0258({
      name: "foo.png",
      size: 4 * 1024 * 1024 + 1,
      type: "image/png",
    }),
  );
  assert.throws(() =>
    validateTextureFile0258({ name: "foo.png", size: 1, type: "image/jpeg" }),
  );
  assert.doesNotThrow(() =>
    validateTextureFile0258({ name: "valid.PNG", size: 11, type: "image/png" }),
  );
});
test("API request endpoints, CAS, and never forwards official session / foreign UUID", async (t) => {
  const recorded = [];
  globalThis.fetch = async (url, opts = {}) => {
    recorded.push({ url, opts });
    if (url.endsWith("/me/textures"))
      return mockResponse({
        realm: "local-project",
        profileUuid: "local",
        profileName: "Tester",
        items: [],
      });
    if (url.endsWith("/library")) return mockResponse({ items: [] });
    return mockResponse({ revision: 4, kind: "skin", active: true });
  };
  const api = new TextureServiceClient0258("https://never.example/", "token");
  await api.identity();
  await api.library();
  await api.select("skin", digest, 3, "slim", "public");
  await api.reset("skin", 4);
  await api.reset("skin", 4, true);
  await api.change(
    "skin",
    { kind: "skin", revision: 4, active: true },
    "classic",
    "private",
  );
  await api.deleteSaved("skin", digest);
  assert.deepEqual(
    recorded.map((r) => [r.opts.method || "GET", new URL(r.url).pathname]),
    [
      ["GET", "/api/v1/me/textures"],
      ["GET", "/api/v1/me/textures/library"],
      ["POST", "/api/v1/me/textures/skin/select"],
      ["POST", "/api/v1/me/textures/skin/reset"],
      ["DELETE", "/api/v1/me/textures/skin"],
      ["PATCH", "/api/v1/me/textures/skin"],
      ["DELETE", "/api/v1/me/textures/library/skin/" + digest],
    ],
  );
  assert.equal(JSON.parse(recorded[2].opts.body).expectedRevision, 3);
  assert.equal(JSON.parse(recorded[2].opts.body).digest, digest);
  assert.equal(
    recorded.every((r) => r.opts.headers.Authorization === "Bearer token"),
    true,
  );
  assert.equal(
    recorded.every(
      (r) =>
        !String(r.opts.body).includes("profileUuid") &&
        !String(r.opts.body).includes("official"),
    ),
    true,
  );
  t.after(() => {
    delete globalThis.fetch;
  });
});
test("concurrent CAS conflict returns 409 and never silently retries", async (t) => {
  let n = 0;
  globalThis.fetch = async () => {
    n++;
    return response({ error: { message: "stale" } }, 409);
  };
  const api = new TextureServiceClient0258("https://never.example", "never");
  await assert.rejects(
    api.select("skin", digest, 2, "classic", "public"),
    (e) => e instanceof TextureServiceError0258 && e.status === 409,
  );
  assert.equal(n, 1);
  t.after(() => {
    delete globalThis.fetch;
  });
});
test("owner-only preview sends Bearer, rejects JSON and revokes invalid digests", async (t) => {
  const seen = [];
  const oldURL = globalThis.URL.createObjectURL;
  globalThis.URL.createObjectURL = () => "blob:test";
  globalThis.fetch = async (url, opts) => {
    seen.push(opts);
    return {
      ...response({}, 200, { "Content-Type": "image/png" }),
      blob: async () => new Blob(["png"], { type: "image/png" }),
    };
  };
  const api = new TextureServiceClient0258("https://never.example", "secret");
  assert.equal(await api.preview("skin", digest), "blob:test");
  assert.equal(seen[0].headers.Authorization, "Bearer secret");
  await assert.rejects(api.preview("skin", "../secret"));
  globalThis.URL.createObjectURL = oldURL;
  t.after(() => {
    delete globalThis.fetch;
  });
});
test("multipart upload uses real XHR progress, Authorization and expectedRevision", async (t) => {
  const events = [];
  class FakeXHR {
    constructor() {
      this.upload = {};
      this.responseText = "";
      this.headers = {};
      events.push(this);
    }
    open(method, url) {
      this.method = method;
      this.url = url;
    }
    setRequestHeader(k, v) {
      this.headers[k] = v;
    }
    send(form) {
      this.form = form;
      this.upload.onprogress?.({
        lengthComputable: true,
        loaded: 50,
        total: 100,
      });
      this.status = 200;
      this.responseText = JSON.stringify({
        data: { assignment: { revision: 1 } },
      });
      this.onload();
    }
  }
  globalThis.XMLHttpRequest = FakeXHR;
  const file = new File(["not-a-real-png"], "test.png", { type: "image/png" });
  const values = [];
  await new TextureServiceClient0258("https://never.example", "token").upload(
    "skin",
    file,
    0,
    "slim",
    "public",
    (p) => values.push(p),
  );
  assert.deepEqual(values, [50, 100]);
  assert.equal(events[0].form.get("expectedRevision"), "0");
  assert.equal(events[0].headers.Authorization, "Bearer token");
  assert.equal(events[0].form.get("model"), "slim");
  t.after(() => {
    delete globalThis.XMLHttpRequest;
  });
});
test("official skin upload crosses only native IPC; no browser bearer or game token", async () => {
  const { OfficialMinecraftClient0257 } =
    await import("../build-tests/official_minecraft_0257.js");
  const previousFetch = globalThis.fetch,
    previousXHR = globalThis.XMLHttpRequest,
    now = Date.now;
  const profile = {
    id: "123456781234123412341234567890ab",
    name: "owner",
    skins: [],
    capes: [],
  };
  const updatedProfile = {
    ...profile,
    skins: [
      {
        id: "new",
        state: "ACTIVE",
        variant: "SLIM",
        url: "https://textures.minecraft.net/texture/a",
      },
    ],
  };
  const requests = [];
  const invoke = async (command, args) => {
    requests.push({ command, args });
    if (command === "official_identity_begin_0262")
      return {
        verificationUri: "https://microsoft.com/link",
        userCode: "AB",
        intervalSeconds: 5,
        expiresIn: 300,
      };
    if (command === "official_identity_poll_0262")
      return { pending: false, profile };
    if (command === "official_identity_status_0262") return profile;
    if (command === "official_identity_texture_0262") return updatedProfile;
  };
  globalThis.fetch = () => {
    throw Error("official renderer fetch is forbidden");
  };
  globalThis.XMLHttpRequest = class {
    constructor() {
      throw Error("official renderer XHR is forbidden");
    }
  };
  try {
    const c = new OfficialMinecraftClient0257(
      "https://never.example",
      "jwt",
      "session",
      invoke,
    );
    await c.begin();
    Date.now = () => now() + 10000;
    await c.poll();
    const bytes = Buffer.alloc(33);
    Buffer.from("89504e470d0a1a0a", "hex").copy(bytes);
    bytes.writeUInt32BE(13, 8);
    bytes.write("IHDR", 12);
    bytes.writeUInt32BE(64, 16);
    bytes.writeUInt32BE(64, 20);
    const file = new File([bytes], "skin.png", { type: "image/png" });
    const progress = [];
    const updated = await c.uploadSkin(file, "slim", (value) =>
      progress.push(value),
    );
    assert.equal(updated.name, "owner");
    assert.deepEqual(progress, [100]);
    const upload = requests.find(
      (r) => r.command === "official_identity_texture_0262",
    );
    assert.equal(upload.args.operation, "uploadSkin");
    assert.equal(upload.args.variant, "slim");
    assert.deepEqual(upload.args.skinBytes, Array.from(bytes));
    assert.equal("session" in upload.args, false);
    assert.equal((await c.profile()).id, profile.id);
  } finally {
    globalThis.fetch = previousFetch;
    globalThis.XMLHttpRequest = previousXHR;
    Date.now = now;
  }
});

test("0.39.4: live Yggdrasil delivery verifies RSA property, UUID and actual PNG SHA-256 without player token", async (t) => {
  const { webcrypto, createHash } = await import("node:crypto");
  const uuid = "123456781234423492340123456789ab";
  const png = Buffer.from("real-public-png-byte-stream");
  const hash = createHash("sha256").update(png).digest("hex");
  const pair = await webcrypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-1",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
    },
    true,
    ["sign", "verify"],
  );
  const publicDER = Buffer.from(
    await webcrypto.subtle.exportKey("spki", pair.publicKey),
  ).toString("base64");
  const keyPEM = `-----BEGIN PUBLIC KEY-----\n${publicDER}\n-----END PUBLIC KEY-----`;
  const encoded = Buffer.from(
    JSON.stringify({
      profileId: uuid,
      profileName: "Tester",
      textures: {
        SKIN: {
          url: `https://never.example/api/v1/textures/blob/${hash}`,
          metadata: { model: "slim" },
        },
      },
    }),
  ).toString("base64");
  const signature = Buffer.from(
    await webcrypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      pair.privateKey,
      new TextEncoder().encode(encoded),
    ),
  ).toString("base64");
  const requests = [];
  let corrupt = "";
  globalThis.fetch = async (url, opts = {}) => {
    requests.push({ url, opts });
    if (url === "https://never.example/")
      return new Response(JSON.stringify({ signaturePublickey: keyPEM }), {
        status: 200,
      });
    if (url.includes("sessionserver/"))
      return new Response(
        JSON.stringify({
          id: corrupt === "identity" ? "f".repeat(32) : uuid,
          properties: [
            {
              name: "textures",
              value: encoded,
              signature: corrupt === "signature" ? "a".repeat(344) : signature,
            },
          ],
        }),
        { status: 200 },
      );
    if (url.includes("/textures/blob/"))
      return new Response(corrupt === "bytes" ? "different-image" : png, {
        status: 200,
        headers: { "Content-Type": "image/png" },
      });
    throw Error("Unexpected URL " + url);
  };
  const api = new TextureServiceClient0258(
    "https://never.example",
    "secret-token",
  );
  await api.verifyYggdrasilDelivery("skin", uuid, hash);
  assert.equal(requests.length, 3);
  assert.equal(
    requests.every(
      (r) =>
        r.opts.credentials === "omit" &&
        r.opts.cache === "no-store" &&
        !("headers" in r.opts),
    ),
    true,
  );
  for (const variant of ["identity", "signature", "bytes"]) {
    corrupt = variant;
    await assert.rejects(
      api.verifyYggdrasilDelivery("skin", uuid, hash),
      Error,
      variant,
    );
  }
  await assert.rejects(
    api.verifyYggdrasilDelivery("cape", uuid, hash),
    /не опубликована/,
  );
  await assert.rejects(
    api.verifyYggdrasilDelivery("skin", "../../bad", hash),
    /UUID/,
  );
  t.after(() => {
    delete globalThis.fetch;
  });
});
