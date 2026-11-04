import test from "node:test";
import assert from "node:assert/strict";
import {
  AuthenticationExperience02610,
  describeAuthenticationFailure02610,
} from "../build-tests/official_auth_experience_02610.js";
import { OfficialMinecraftClient0257 } from "../build-tests/official_minecraft_0257.js";

const alpha = {
  id: "0123456789abcdef0123456789abcdef",
  name: "Alpha",
  skins: [],
  capes: [],
};
const bravo = {
  id: "abcdef0123456789abcdef0123456789",
  name: "Bravo",
  skins: [],
  capes: [],
};
const defer = () => {
  let resolve, reject;
  const promise = new Promise((a, b) => {
    resolve = a;
    reject = b;
  });
  return { promise, resolve, reject };
};
const fixture = () => {
  let selected = alpha;
  let profiles = [alpha, bravo];
  let links = [];
  const calls = [];
  const overrides = new Map();
  const native = async (command, args) => {
    calls.push({ command, args });
    if (overrides.has(command)) return overrides.get(command)(args);
    switch (command) {
      case "official_identity_status_0262":
        return selected;
      case "official_identity_accounts_0267":
        return profiles.map((p) => ({
          id: p.id,
          name: p.name,
          active: p.id === selected?.id,
        }));
      case "official_identity_links_0268":
        return links;
      case "official_identity_select_0267":
        selected = profiles.find((p) => p.id === args.accountId);
        return selected;
      case "official_identity_refresh_0267":
        return selected;
      case "official_identity_browser_login_0263":
        selected = bravo;
        return selected;
      case "official_identity_begin_0262":
        return {
          verificationUri: "https://microsoft.com/devicelogin",
          userCode: "ABCD-WXYZ",
          intervalSeconds: 5,
          expiresIn: 900,
        };
      case "official_identity_wait_device_0264":
        selected = bravo;
        return selected;
      case "official_identity_cancel_0262":
        return;
      case "official_identity_logout_0267":
        profiles = profiles.filter((p) => p.id !== args.accountId);
        selected = profiles[0] || null;
        return;
      case "official_identity_link_0268":
        links.push({
          minecraftUuid: args.accountId,
          minecraftName: selected.name,
          verifiedAt: "2026-10-24",
        });
        return links[0];
      case "official_identity_unlink_0268":
        links = links.filter((link) => link.minecraftUuid !== args.accountId);
        return;
      case "official_identity_texture_0262":
        return selected;
      default:
        throw Error(`Unexpected command ${command}`);
    }
  };
  const client = new OfficialMinecraftClient0257(
    "https://backend.example",
    "platform-jwt",
    "session",
    native,
  );
  const events = [];
  const experience = new AuthenticationExperience02610(client, (profile) =>
    events.push(profile),
  );
  return {
    experience,
    events,
    calls,
    overrides,
    client,
    getSelected: () => selected,
  };
};

// Wait until an async operation is observed, without provider/network sleeps.
const waitFor = async (predicate) => {
  for (let i = 0; i < 30; i++) {
    if (predicate()) return;
    await new Promise((resolve) => setImmediate(resolve));
  }
  throw Error("condition not reached");
};

test("restores verified native profile and directory without revealing credentials", async () => {
  const f = fixture();
  await f.experience.initialize();
  assert.equal(f.experience.snapshot.initialized, true);
  assert.equal(f.experience.snapshot.profile.id, alpha.id);
  assert.equal(f.experience.snapshot.accounts.length, 2);
  assert.deepEqual(f.events.at(-1), alpha);
  assert.ok(
    f.calls.every(
      (call) =>
        !("minecraftAccessToken" in call.args) &&
        !("refreshToken" in call.args),
    ),
  );
  assert.equal(f.experience.snapshot.activity, null);
});

test("switch, refresh, Never linking, unlinking and selective logout update UI and parent", async () => {
  const f = fixture();
  await f.experience.initialize();
  await f.experience.select(bravo.id);
  assert.equal(f.experience.snapshot.profile.id, bravo.id);
  await f.experience.refresh();
  assert.equal(f.experience.snapshot.profile.id, bravo.id);
  await f.experience.link(bravo.id);
  assert.equal(f.experience.snapshot.links[0].minecraftUuid, bravo.id);
  await f.experience.unlink(bravo.id);
  assert.deepEqual(f.experience.snapshot.links, []);
  await f.experience.logout(bravo.id);
  assert.equal(f.experience.snapshot.accounts.length, 1);
  assert.equal(f.experience.snapshot.profile.id, alpha.id);
  assert.equal(f.events.at(-1)?.id, alpha.id);
  await f.experience.logout(alpha.id);
  assert.equal(f.experience.snapshot.profile, null);
  assert.equal(f.experience.snapshot.accounts.length, 0);
});

test("revoked refresh immediately invalidates launch readiness, but retains local directory", async () => {
  const f = fixture();
  await f.experience.initialize();
  f.overrides.set("official_identity_refresh_0267", () => {
    throw Error("invalid_grant refresh_token=supersecret");
  });
  await f.experience.refresh();
  assert.equal(f.experience.snapshot.profile, null);
  assert.equal(f.events.at(-1), null);
  assert.equal(f.experience.snapshot.accounts.length, 2);
  assert.match(f.experience.snapshot.issue, /вход Microsoft заново/);
  assert.doesNotMatch(JSON.stringify(f.experience.snapshot), /supersecret/);
});

test("never trusts a provider profile that mismatches the active vault UUID", async () => {
  const f = fixture();
  f.overrides.set("official_identity_status_0262", () => bravo);
  await f.experience.initialize();
  assert.equal(f.experience.snapshot.profile, null);
  assert.equal(f.events.at(-1), null);
});

test("browser login returns verified account, supports re-login and keeps accounts", async () => {
  const f = fixture();
  await f.experience.initialize();
  await f.experience.browserLogin();
  assert.equal(f.experience.snapshot.profile.id, bravo.id);
  assert.equal(f.experience.snapshot.accounts.length, 2);
  assert.ok(
    f.calls.some(
      (call) => call.command === "official_identity_browser_login_0263",
    ),
  );
});

test("cancel of slow browser flow discards stale success and allows subsequent login", async () => {
  const f = fixture();
  await f.experience.initialize();
  const pending = defer();
  f.overrides.set(
    "official_identity_browser_login_0263",
    () => pending.promise,
  );
  const login = f.experience.browserLogin();
  await waitFor(() => f.experience.snapshot.activity === "browser");
  await f.experience.cancelLogin();
  pending.resolve(bravo);
  await login;
  assert.equal(f.experience.snapshot.profile.id, alpha.id);
  assert.equal(f.experience.snapshot.activity, null);
  assert.equal(f.experience.snapshot.device, null);
  f.overrides.delete("official_identity_browser_login_0263");
  await f.experience.browserLogin();
  assert.equal(f.experience.snapshot.profile.id, bravo.id);
});

test("Device Code automatically waits in Rust, publishes deadline, cancel fences late response", async () => {
  const f = fixture();
  await f.experience.initialize();
  const pending = defer();
  f.overrides.set("official_identity_wait_device_0264", () => pending.promise);
  const login = f.experience.deviceLogin();
  await waitFor(() => Boolean(f.experience.snapshot.device));
  const state = f.experience.snapshot;
  assert.equal(state.device.userCode, "ABCD-WXYZ");
  assert.ok(state.deviceExpiresAt > Date.now());
  assert.equal(state.activity, "device");
  await f.experience.cancelLogin();
  pending.resolve(bravo);
  await login;
  assert.equal(f.experience.snapshot.profile.id, alpha.id);
  assert.equal(f.experience.snapshot.device, null);
  assert.equal(f.experience.snapshot.activity, null);
});

test("blocks concurrent selection while one native request is running", async () => {
  const f = fixture();
  await f.experience.initialize();
  const pending = defer();
  f.overrides.set("official_identity_select_0267", () => pending.promise);
  const a = f.experience.select(bravo.id);
  await waitFor(() => f.experience.snapshot.activity === "select");
  await f.experience.select(alpha.id);
  assert.equal(
    f.calls.filter((c) => c.command === "official_identity_select_0267").length,
    1,
  );
  pending.resolve(alpha);
  await a;
  assert.equal(f.experience.snapshot.activity, null);
});

test("link service outage does not hide a verified gameplay profile", async () => {
  const f = fixture();
  f.overrides.set("official_identity_links_0268", () => {
    throw Error("HTTP 503");
  });
  await f.experience.initialize();
  assert.equal(f.experience.snapshot.profile.id, alpha.id);
  assert.equal(f.experience.snapshot.links, null);
  assert.match(f.experience.snapshot.linksIssue, /недоступна/);
});

test("disposing during slow login prevents any parent or view mutation", async () => {
  const f = fixture();
  await f.experience.initialize();
  const pending = defer();
  f.overrides.set(
    "official_identity_browser_login_0263",
    () => pending.promise,
  );
  const login = f.experience.browserLogin();
  await waitFor(() => f.experience.snapshot.activity === "browser");
  const prior = f.events.length;
  f.experience.dispose();
  pending.resolve(bravo);
  await login;
  assert.equal(f.events.length, prior);
});

test("error display uses allowlisted categories, never secrets or provider URL", () => {
  assert.match(
    describeAuthenticationFailure02610("403 Invalid app registration"),
    /не допущено/,
  );
  assert.match(describeAuthenticationFailure02610("XSTS XErr family"), /Xbox/);
  assert.equal(
    describeAuthenticationFailure02610(
      "https://server.example/callback?access_token=SECRET",
    ),
    "Операция с игровым аккаунтом не выполнена. Повторите попытку или проверьте диагностику.",
  );
  assert.doesNotMatch(
    describeAuthenticationFailure02610("refresh_token=SECRET"),
    /SECRET/,
  );
});

test("browser cancel during preliminary native cancel cannot start a new flow after cancellation", async () => {
  const gate = defer();
  const calls = [];
  const client = new OfficialMinecraftClient0257(
    "https://backend.example",
    "token",
    "sid",
    async (command) => {
      calls.push(command);
      if (command === "official_identity_cancel_0262") {
        if (calls.filter((x) => x === command).length === 1) await gate.promise;
        return;
      }
      if (command === "official_identity_browser_login_0263")
        throw Error("must not launch");
      throw Error(command);
    },
  );
  const start = client.browserLogin();
  await waitFor(() => calls.includes("official_identity_cancel_0262"));
  await client.cancel();
  gate.resolve();
  await assert.rejects(start, /отменена/);
  assert.equal(calls.includes("official_identity_browser_login_0263"), false);
});

test("Device Code cancel during initial request cannot create stale pending flow", async () => {
  const gate = defer();
  const calls = [];
  const client = new OfficialMinecraftClient0257(
    "https://backend.example",
    "token",
    "sid",
    async (command) => {
      calls.push(command);
      if (command === "official_identity_cancel_0262") {
        if (calls.filter((x) => x === command).length === 1) await gate.promise;
        return;
      }
      if (command === "official_identity_begin_0262")
        throw Error("must not begin");
      throw Error(command);
    },
  );
  const start = client.begin();
  await waitFor(() => calls.includes("official_identity_cancel_0262"));
  await client.cancel();
  gate.resolve();
  await assert.rejects(start, /отменена/);
  assert.equal(calls.includes("official_identity_begin_0262"), false);
});

test("native cancellation locks the UI until completion; cannot race a fresh browser login", async () => {
  const f = fixture();
  await f.experience.initialize();
  const browser = defer(),
    cancel = defer();
  f.overrides.set(
    "official_identity_browser_login_0263",
    () => browser.promise,
  );
  f.overrides.set("official_identity_cancel_0262", () => cancel.promise);
  const login = f.experience.browserLogin();
  await waitFor(() => f.experience.snapshot.activity === "browser");
  const cancelling = f.experience.cancelLogin();
  assert.equal(f.experience.snapshot.activity, "cancel");
  await f.experience.browserLogin();
  assert.equal(
    f.calls.filter((c) => c.command === "official_identity_browser_login_0263")
      .length,
    0,
  );
  cancel.resolve();
  await cancelling;
  browser.resolve(bravo);
  await login;
  assert.equal(f.experience.snapshot.activity, null);
  assert.equal(f.experience.snapshot.profile.id, alpha.id);
});
