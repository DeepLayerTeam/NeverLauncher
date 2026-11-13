import test from "node:test";
import assert from "node:assert/strict";
import {
  AuthenticationExperience02610,
  describeAuthenticationFailure02610,
} from "../build-tests/official_auth_experience.js";
import { OfficialMinecraftClient0257 } from "../build-tests/official_minecraft.js";

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
        throw Error(`Непредусмотренная команда ${command}`);
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

// Ожидайте наблюдения асинхронной операции без искусственных пауз провайдера или сети.
const waitFor = async (predicate) => {
  for (let i = 0; i < 30; i++) {
    if (predicate()) return;
    await new Promise((resolve) => setImmediate(resolve));
  }
  throw Error("Условие не выполнено за отведённое число проверок");
};

test("Восстанавливает проверенный нативный профиль и каталог без раскрытия учётных данных", async () => {
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

test("Переключение, обновление, привязка и отвязка Launcher и выборочный выход обновляют интерфейс и родителя", async () => {
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

test("Отозванное обновление немедленно запрещает запуск, сохраняя локальный каталог", async () => {
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

test("Не доверяет профилю провайдера при несовпадении UUID активного хранилища", async () => {
  const f = fixture();
  f.overrides.set("official_identity_status_0262", () => bravo);
  await f.experience.initialize();
  assert.equal(f.experience.snapshot.profile, null);
  assert.equal(f.events.at(-1), null);
});

test("Вход через браузер возвращает проверенную учётную запись, допускает повторный вход и сохраняет аккаунты", async () => {
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

test("Отмена медленного входа отбрасывает запоздалый успех и разрешает новый вход", async () => {
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

test("Код устройства обрабатывается в Rust с предельным сроком; отмена блокирует поздний ответ", async () => {
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

test("Блокирует параллельный выбор во время нативного запроса", async () => {
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

test("Недоступность сервиса привязки не скрывает проверенный игровой профиль", async () => {
  const f = fixture();
  f.overrides.set("official_identity_links_0268", () => {
    throw Error("HTTP 503");
  });
  await f.experience.initialize();
  assert.equal(f.experience.snapshot.profile.id, alpha.id);
  assert.equal(f.experience.snapshot.links, null);
  assert.match(f.experience.snapshot.linksIssue, /недоступна/);
});

test("Завершение во время медленного входа исключает изменение родителя и представления", async () => {
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

test("Ошибки отображаются только из разрешённых категорий, без секретов и URL провайдера", () => {
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

test("Отмена входа через браузер не запускает новый процесс при незавершённой нативной отмене", async () => {
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
        throw Error("Запуск не должен выполняться");
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

test("Отмена кода устройства во время первого запроса не оставляет устаревший процесс", async () => {
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
        throw Error("Операция не должна начинаться");
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

test("Нативная отмена блокирует интерфейс до завершения и исключает гонку с новым входом", async () => {
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
