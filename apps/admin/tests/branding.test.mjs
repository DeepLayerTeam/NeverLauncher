import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
const prestarterDir = fileURLToPath(
  new URL("../../../prestarter/", import.meta.url),
);
const hasGo = spawnSync("go", ["version"]).status === 0;
import {
  validateBrand0355,
  verifyBootstrap0355,
  signBranding0355,
} from "../src/admin/branding_0355.ts";
if (!globalThis.crypto) globalThis.crypto = webcrypto;
const enc = new TextEncoder();
function toHex(bytes) {
  return Buffer.from(bytes).toString("hex");
}
async function keypair() {
  const k = await crypto.subtle.generateKey("Ed25519", true, [
    "sign",
    "verify",
  ]);
  const pk = toHex(await crypto.subtle.exportKey("raw", k.publicKey));
  const secret = new Uint8Array(
    await crypto.subtle.exportKey("pkcs8", k.privateKey),
  );
  return {
    key: k.privateKey,
    public: pk,
    seed: toHex(secret.subarray(secret.length - 32)),
  };
}
async function signed(key, data) {
  return toHex(await crypto.subtle.sign("Ed25519", key, data));
}
const b64 = (b) => Buffer.from(b).toString("base64");
function bootstrap(root) {
  const a = {
    url: "https://files.example.com/a",
    sha256: "ab".repeat(32),
    size: 123,
  };
  return {
    schemaVersion: "1.0",
    projectId: "example",
    profileId: "fabric",
    channel: "stable",
    backendUrl: "https://api.example.com",
    profilePublicKey: root,
    manifest: a,
    javaManifest: a,
    targets: [
      {
        os: "linux",
        arch: "amd64",
        components: [
          { name: "desktop", ...a },
          { name: "runtime", ...a },
          { name: "guard", ...a },
        ],
      },
    ],
  };
}
const brand = {
  logoPng:
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGPgEpH7DwABpAE8k4sOtwAAAABJRU5ErkJggg==",
  displayName: "Example Launcher",
  publisher: "Example",
  locale: "ru",
  accentColor: "#32cc44",
  backgroundColor: "#101827",
  textColor: "#ffffff",
  news: [{ title: "Обновление", url: "https://example.com/news" }],
};
test("root signed v1 -> branding edit -> new signed payload verifies; tampering rejected", async () => {
  const root = await keypair();
  const raw = enc.encode(JSON.stringify(bootstrap(root.public)));
  const original = JSON.stringify({
    schemaVersion: "1.0",
    payload: b64(raw),
    signature: await signed(root.key, raw),
  });
  const output = await signBranding0355(
    original,
    root.public,
    root.seed,
    brand,
  );
  const result = await verifyBootstrap0355(output, root.public);
  assert.deepEqual(result.payload.branding, brand);
  assert.equal(result.payload.projectId, "example");
  if (hasGo) {
    const dir = mkdtempSync(join(tmpdir(), "brand-"));
    try {
      writeFileSync(join(dir, "bootstrap.signed.json"), output);
      writeFileSync(join(dir, "root.hex"), root.public);
      const verified = execFileSync(
        "go",
        [
          "run",
          "./cmd/verify-branding",
          "--config",
          join(dir, "bootstrap.signed.json"),
          "--root-key-file",
          join(dir, "root.hex"),
        ],
        { cwd: prestarterDir, encoding: "utf8" },
      );
      const data = JSON.parse(verified);
      assert.equal(data.status, "verified");
      assert.equal(data.branding.displayName, brand.displayName);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
  const changed = JSON.parse(output);
  changed.payload = b64(
    enc.encode(JSON.stringify({ ...result.payload, projectId: "other" })),
  );
  await assert.rejects(
    verifyBootstrap0355(JSON.stringify(changed), root.public),
    /подпись/,
  );
  const wrong = await keypair();
  await assert.rejects(
    signBranding0355(original, root.public, wrong.seed, brand),
    /подпись/,
  );
});
test("delegated signed v2 -> root policy -> modified signed bootstrap remains v2", async () => {
  const root = await keypair(),
    delegate = await keypair();
  const now = new Date();
  const policy = {
    schemaVersion: "1.0",
    domain: "launcher.trust.v1",
    epoch: 11,
    issuedAt: new Date(now.getTime() - 60000).toISOString().slice(0, 19) + "Z",
    expiresAt:
      new Date(now.getTime() + 3600000).toISOString().slice(0, 19) + "Z",
    keys: [
      {
        id: "owner-bootstrap",
        role: "bootstrap",
        status: "active",
        publicKey: delegate.public,
        notBefore:
          new Date(now.getTime() - 300000).toISOString().slice(0, 19) + "Z",
      },
    ],
  };
  const policyRaw = enc.encode(JSON.stringify(policy));
  const policyDoc = JSON.stringify({
    schemaVersion: "1.0",
    payload: b64(policyRaw),
    rootSignature: await signed(
      root.key,
      Buffer.concat([enc.encode("Launcher-Trust-Policy-v1\n"), policyRaw]),
    ),
  });
  const signedAt = now.toISOString().slice(0, 19) + "Z";
  const payload = enc.encode(JSON.stringify(bootstrap(root.public)));
  const message = Buffer.concat([
    enc.encode(`Launcher-Bootstrap-v2\nowner-bootstrap\n11\n${signedAt}\n`),
    payload,
  ]);
  const original = JSON.stringify({
    schemaVersion: "2.0",
    payload: b64(payload),
    signature: await signed(delegate.key, message),
    keyId: "owner-bootstrap",
    trustEpoch: 11,
    signedAt,
  });
  const modified = await signBranding0355(
    original,
    root.public,
    delegate.seed,
    brand,
    policyDoc,
  );
  assert.equal(
    (await verifyBootstrap0355(modified, root.public, policyDoc)).payload
      .branding.displayName,
    "Example Launcher",
  );
  if (hasGo) {
    const dir = mkdtempSync(join(tmpdir(), "brand-delegated-"));
    try {
      writeFileSync(join(dir, "bootstrap.signed.json"), modified);
      writeFileSync(join(dir, "root.hex"), root.public);
      writeFileSync(join(dir, "policy.json"), policyDoc);
      const actual = JSON.parse(
        execFileSync(
          "go",
          [
            "run",
            "./cmd/verify-branding",
            "--config",
            join(dir, "bootstrap.signed.json"),
            "--root-key-file",
            join(dir, "root.hex"),
            "--trust-policy",
            join(dir, "policy.json"),
          ],
          { cwd: prestarterDir, encoding: "utf8" },
        ),
      );
      assert.equal(actual.schemaVersion, "2.0");
      assert.equal(actual.branding.newsCount, 1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
  await assert.rejects(verifyBootstrap0355(modified, root.public), /policy/);
  await assert.rejects(
    signBranding0355(original, root.public, root.seed, brand, policyDoc),
    /подпись/,
  );
  await assert.rejects(
    verifyBootstrap0355(modified, delegate.public, policyDoc),
    /подпись/,
  );
});
test("unsafe colors, Javascript links, SVG and oversized images refused before signing", () => {
  assert.throws(
    () =>
      validateBrand0355({ ...brand, accentColor: "red; url(javascript:evil)" }),
    /Цвет/,
  );
  assert.throws(
    () =>
      validateBrand0355({
        ...brand,
        news: [{ title: "bad", url: "javascript:alert(1)" }],
      }),
    /ссылк/,
  );
  assert.throws(
    () =>
      validateBrand0355({ ...brand, logoPng: b64('<svg onload="alert(1)"/>') }),
    /PNG/,
  );
  assert.throws(
    () => validateBrand0355({ ...brand, splashPng: "A".repeat(200000) }),
    /PNG/,
  );
  assert.throws(
    () => validateBrand0355({ ...brand, locale: "../en" }),
    /ru и en/,
  );
});
