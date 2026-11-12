import { test } from "node:test";
import assert from "node:assert/strict";
import { OfficialMinecraftClient0257 } from "../build-tests/official_minecraft_0257.js";
const profile = {
  id: "123456781234123412341234567890ab",
  name: "Owner",
  skins: [],
  capes: [],
};

test("Официальный сценарий использует только нативную границу; IPC-ответы не содержат билеты и игровые учётные данные", async () => {
  const requests = [];
  const invoke = async (command, args) => {
    requests.push({ command, args });
    switch (command) {
      case "official_identity_cancel_0262":
        return;
      case "official_identity_begin_0262":
        return {
          verificationUri: "https://microsoft.com/devicelogin",
          userCode: "ABCD",
          intervalSeconds: 5,
          expiresIn: 900,
        };
      case "official_identity_poll_0262":
        return { pending: false, profile };
      case "official_identity_status_0262":
        return profile;
      case "official_identity_disconnect_0262":
        return;
      default:
        throw Error(command);
    }
  };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = () => {
    throw Error("Интерфейс не должен напрямую вызывать официальный API");
  };
  const originalDate = Date.now;
  try {
    const c = new OfficialMinecraftClient0257(
      "https://backend.example",
      "access",
      "session",
      invoke,
    );
    assert.equal((await c.begin()).userCode, "ABCD");
    Date.now = () => originalDate() + 10000;
    assert.deepEqual((await c.poll()).profile, profile);
    assert.equal(c.linked, true);
    assert.equal((await c.profile()).name, "Owner");
    await assert.rejects(c.credentials(), /native manager/);
    assert.equal(
      requests.some(
        (r) =>
          r.command === "official_identity_poll_0262" &&
          r.args.context.launcherSessionId === "session",
      ),
      true,
    );
    assert.equal(
      requests.some(
        (r) => r.command === "official_identity_launch_credentials",
      ),
      false,
    );
    assert.equal(
      requests.some((r) => JSON.stringify(r.args).includes("official-jwt")),
      false,
    );
    await c.disconnect();
    assert.equal(c.linked, false);
  } finally {
    globalThis.fetch = originalFetch;
    Date.now = originalDate;
  }
});

test("Восстановление нативного профиля не возвращает билет сеанса", async () => {
  const commands = [];
  const c = new OfficialMinecraftClient0257(
    "https://backend.example",
    "token-123456789",
    "session",
    async (cmd) => {
      commands.push(cmd);
      return cmd === "official_identity_status_0262" ? profile : undefined;
    },
  );
  assert.equal(c.linked, false);
  assert.equal((await c.restore())?.id, profile.id);
  assert.equal(c.linked, true);
  assert.deepEqual(commands, ["official_identity_status_0262"]);
});

test("Отклоняет преждевременный опрос до нативного запроса кода устройства", async () => {
  const commands = [];
  const c = new OfficialMinecraftClient0257(
    "https://backend.example",
    "token-123456789",
    "session",
    async (cmd) => {
      commands.push(cmd);
      return cmd === "official_identity_begin_0262"
        ? {
            verificationUri: "https://microsoft.com/link",
            userCode: "A",
            intervalSeconds: 5,
            expiresIn: 900,
          }
        : undefined;
    },
  );
  await c.begin();
  await assert.rejects(c.poll(), /интервал/);
  assert.equal(commands.includes("official_identity_poll_0262"), false);
});

test("Билеты нативной учётной записи и поля токенов не передаются в предпросмотр", async () => {
  const calls = [];
  const owned = {
    ...profile,
    capes: [
      {
        id: "cape1",
        state: "INACTIVE",
        url: "https://textures.minecraft.net/texture/a",
      },
    ],
  };
  const selected = {
    ...owned,
    capes: [{ ...owned.capes[0], state: "ACTIVE" }],
  };
  const c = new OfficialMinecraftClient0257(
    "https://backend.example",
    "platform-token",
    "sid",
    async (cmd, args) => {
      calls.push({ cmd, args });
      if (cmd === "official_identity_status_0262") return owned;
      if (cmd === "official_identity_texture_0262")
        return args.operation === "selectCape" ? selected : owned;
      return owned;
    },
  );
  await c.selectCape("cape1");
  await c.resetCape();
  await c.resetSkin();
  assert.ok(
    calls
      .filter((x) => x.cmd === "official_identity_texture_0262")
      .every((x) => !("session" in x.args) && !("accessToken" in x.args)),
  );
});

test("PKCE браузера вызывается только нативной командой и возвращает метаданные профиля", async () => {
  const calls = [];
  const client = new OfficialMinecraftClient0257(
    "https://backend.example",
    "platform-token",
    "session-1",
    async (cmd, args) => {
      calls.push({ cmd, args });
      if (cmd === "official_identity_browser_login_0263") return profile;
      if (cmd === "official_identity_cancel_0262") return;
      throw Error("Непредусмотренная команда " + cmd);
    },
  );
  assert.deepEqual(await client.browserLogin(), profile);
  assert.equal(client.linked, true);
  assert.deepEqual(
    calls.map((c) => c.cmd),
    ["official_identity_cancel_0262", "official_identity_browser_login_0263"],
  );
  assert.ok(
    calls.every(
      (c) =>
        !JSON.stringify(c.args).includes("verifier") &&
        !JSON.stringify(c.args).includes("code_challenge") &&
        !JSON.stringify(c.args).includes("microsoftToken"),
    ),
  );
});

test("Отменённый вход через браузер не передаёт запоздалый ответ процессу отображения", async () => {
  let complete;
  const pending = new Promise((resolve) => {
    complete = resolve;
  });
  const client = new OfficialMinecraftClient0257(
    "https://backend.example",
    "platform-token",
    "session-1",
    async (cmd) => {
      if (cmd === "official_identity_cancel_0262") return;
      if (cmd === "official_identity_browser_login_0263") return pending;
      throw Error("Непредусмотренная команда " + cmd);
    },
  );
  const login = client.browserLogin();
  await new Promise((resolve) => setImmediate(resolve));
  await client.cancel();
  complete(profile);
  await assert.rejects(login, /отменена/);
  assert.equal(client.linked, false);
});

test("Нативное ожидание кода устройства автоматически возвращает только проверенный профиль", async () => {
  const calls = [];
  const c = new OfficialMinecraftClient0257(
    "https://backend.example",
    "platform-token",
    "session-0264",
    async (cmd, args) => {
      calls.push({ cmd, args });
      if (cmd === "official_identity_cancel_0262") return;
      if (cmd === "official_identity_begin_0262")
        return {
          verificationUri: "https://microsoft.com/link",
          userCode: "ABCD-EFGH",
          intervalSeconds: 5,
          expiresIn: 900,
        };
      if (cmd === "official_identity_wait_device_0264") return profile;
      throw new Error("Неожиданная нативная команда: " + cmd);
    },
  );
  await c.begin();
  assert.deepEqual(await c.waitDevice(), profile);
  assert.equal(c.linked, true);
  assert.deepEqual(
    calls.map((r) => r.cmd),
    [
      "official_identity_cancel_0262",
      "official_identity_begin_0262",
      "official_identity_wait_device_0264",
    ],
  );
  assert.ok(
    calls.every(
      (r) =>
        !("ticket" in r.args) &&
        !("deviceCode" in r.args) &&
        !("refreshToken" in r.args),
    ),
  );
});

test("Отменённое ожидание кода устройства не принимает запоздалый нативный результат", async () => {
  let release;
  const delayed = new Promise((resolve) => {
    release = resolve;
  });
  const c = new OfficialMinecraftClient0257(
    "https://backend.example",
    "platform-token",
    "session-0264",
    async (cmd) => {
      if (cmd === "official_identity_cancel_0262") return;
      if (cmd === "official_identity_begin_0262")
        return {
          verificationUri: "https://microsoft.com/link",
          userCode: "ABCD",
          intervalSeconds: 5,
          expiresIn: 900,
        };
      if (cmd === "official_identity_wait_device_0264") return delayed;
      throw new Error(cmd);
    },
  );
  await c.begin();
  const waiting = c.waitDevice();
  await c.cancel();
  release(profile);
  await assert.rejects(waiting, /отменена/);
  assert.equal(c.linked, false);
});

test("Замена кода устройства отменяет предыдущее нативное ожидание", async () => {
  let finish;
  const waitingNative = new Promise((resolve) => {
    finish = resolve;
  });
  let index = 0;
  const c = new OfficialMinecraftClient0257(
    "https://backend.example",
    "platform-token",
    "session-0264",
    async (cmd) => {
      if (cmd === "official_identity_cancel_0262") return;
      if (cmd === "official_identity_begin_0262")
        return {
          verificationUri: "https://microsoft.com/link",
          userCode: String(++index),
          intervalSeconds: 5,
          expiresIn: 900,
        };
      if (cmd === "official_identity_wait_device_0264") return waitingNative;
      throw new Error(cmd);
    },
  );
  await c.begin();
  const waiting = c.waitDevice();
  await c.begin();
  finish(profile);
  await assert.rejects(waiting, /отменена/);
  assert.equal(c.linked, false);
});

test("Текст нативной ошибки после отмены очищается перед следующим запросом кода устройства", async () => {
  let rejectOld;
  let started = 0;
  const native = new Promise((_, reject) => {
    rejectOld = reject;
  });
  const c = new OfficialMinecraftClient0257(
    "https://backend.example",
    "platform-token",
    "sid-0264",
    async (cmd) => {
      if (cmd === "official_identity_cancel_0262") return;
      if (cmd === "official_identity_begin_0262")
        return {
          verificationUri: "https://microsoft.com/link",
          userCode: String(++started),
          intervalSeconds: 5,
          expiresIn: 900,
        };
      if (cmd === "official_identity_wait_device_0264") return native;
      throw new Error(cmd);
    },
  );
  await c.begin();
  const pending = c.waitDevice();
  await c.begin();
  rejectOld("Сервис официальной авторизации недоступен");
  await assert.rejects(pending, /отменена/);
  assert.equal(c.linked, false);
});

test("0.26.7: список аккаунтов, выбор, принудительное обновление и выход используют нативные вызовы без секретов", async () => {
  const a = {
    ...profile,
    id: "0123456789abcdef0123456789abcdef",
    name: "Alpha",
  };
  const b = {
    ...profile,
    id: "abcdef0123456789abcdef0123456789",
    name: "Bravo",
  };
  let selected = a,
    accounts = [a, b],
    commandLog = [];
  const client = new OfficialMinecraftClient0257(
    "https://backend.example",
    "access",
    "sid",
    async (cmd, args) => {
      commandLog.push({ cmd, args });
      switch (cmd) {
        case "official_identity_accounts_0267":
          return accounts.map((p) => ({
            id: p.id,
            name: p.name,
            active: p.id === selected?.id,
          }));
        case "official_identity_status_0262":
          return selected;
        case "official_identity_select_0267":
          selected = accounts.find((p) => p.id === args.accountId);
          return selected;
        case "official_identity_refresh_0267":
          return selected;
        case "official_identity_logout_0267":
          accounts = accounts.filter((p) => p.id !== args.accountId);
          selected = accounts[0] || null;
          return;
      }
      throw Error(cmd);
    },
  );
  assert.equal((await client.restore()).id, a.id);
  assert.deepEqual(
    (await client.accounts()).map((p) => p.name),
    ["Alpha", "Bravo"],
  );
  assert.equal((await client.selectAccount(b.id)).id, b.id);
  assert.equal((await client.refresh()).id, b.id);
  assert.equal((await client.logout(b.id))?.id, a.id);
  assert.equal((await client.accounts()).length, 1);
  assert.equal(await client.logout(a.id), null);
  assert.equal(client.linked, false);
  const dangerous =
    /refreshToken|minecraftToken|accessToken|sessionTicket|codeVerifier/;
  assert.ok(commandLog.every((r) => !dangerous.test(JSON.stringify(r.args))));
  assert.ok(commandLog.some((r) => r.cmd === "official_identity_refresh_0267"));
});

test("0.26.7: отклонённое переключение не подменяет UUID", async () => {
  const p = { ...profile, id: "0123456789abcdef0123456789abcdef" };
  const client = new OfficialMinecraftClient0257(
    "https://backend.example",
    "access",
    "sid",
    async (cmd) => {
      if (cmd === "official_identity_status_0262") return p;
      if (cmd === "official_identity_select_0267")
        throw new Error("Несовпадение UUID Minecraft");
      throw Error(cmd);
    },
  );
  await client.restore();
  await assert.rejects(
    client.selectAccount("deadbeefdeadbeefdeadbeefdeadbeef"),
    /UUID mismatch/,
  );
  assert.equal(client.linked, true);
});

test("0.26.7: отмена добавления не отключает ранее восстановленный аккаунт", async () => {
  const client = new OfficialMinecraftClient0257(
    "https://backend.example",
    "access",
    "sid",
    async (cmd) => {
      if (cmd === "official_identity_status_0262") return profile;
      if (cmd === "official_identity_cancel_0262") return;
      throw Error(cmd);
    },
  );
  await client.restore();
  await client.cancel();
  assert.equal(client.linked, true);
});

test("0.26.7: устаревшее переключение аккаунта отклоняется после локального сброса", async () => {
  let resolve;
  const pending = new Promise((r) => (resolve = r));
  const client = new OfficialMinecraftClient0257(
    "https://backend.example",
    "access",
    "sid",
    async (cmd) => {
      if (cmd === "official_identity_select_0267") return pending;
      throw Error(cmd);
    },
  );
  const switching = client.selectAccount("0123456789abcdef0123456789abcdef");
  client.clear();
  resolve(profile);
  await assert.rejects(switching, /отменено/);
  assert.equal(client.linked, false);
});

test("0.26.8: привязка Launcher использует нативные команды и не раскрывает токен Minecraft", async () => {
  const calls = [];
  const client = new OfficialMinecraftClient0257(
    "https://backend.example",
    "platform-token",
    "sid",
    async (command, args) => {
      calls.push({ command, args });
      if (command === "official_identity_links_0268")
        return [
          {
            minecraftUuid: profile.id,
            minecraftName: profile.name,
            verifiedAt: "2026-10-23T00:00:00Z",
          },
        ];
      if (command === "official_identity_link_0268")
        return {
          minecraftUuid: profile.id,
          minecraftName: profile.name,
          verifiedAt: "2026-10-23T00:00:00Z",
        };
      if (command === "official_identity_unlink_0268") return;
      throw Error(command);
    },
  );
  assert.equal((await client.launcherLinks())[0].minecraftUuid, profile.id);
  await assert.rejects(client.linkToLauncher(profile.id, false), /подтверждение/i);
  assert.equal(
    (await client.linkToLauncher(profile.id, true)).minecraftName,
    "Owner",
  );
  await assert.rejects(
    client.unlinkFromLauncher(profile.id, false),
    /подтверждение/i,
  );
  await client.unlinkFromLauncher(profile.id, true);
  assert.deepEqual(
    calls.map((x) => x.command),
    [
      "official_identity_links_0268",
      "official_identity_link_0268",
      "official_identity_unlink_0268",
    ],
  );
  assert.ok(
    calls.every(
      (x) =>
        !JSON.stringify(x.args).includes("minecraftAccessToken") &&
        !JSON.stringify(x.args).includes("refreshToken"),
    ),
  );
});

test("0.39.5: нативная запись разрешена только для своих плащей, требуется подтверждённый активный плащ", async () => {
  const owned = {
    ...profile,
    capes: [
      {
        id: "owned",
        state: "INACTIVE",
        url: "https://textures.minecraft.net/texture/abc",
      },
    ],
  };
  const calls = [];
  let result = { ...owned, capes: [{ ...owned.capes[0], state: "ACTIVE" }] };
  const client = new OfficialMinecraftClient0257(
    "https://backend.example",
    "access",
    "s1",
    async (cmd, args) => {
      calls.push({ cmd, args });
      if (cmd === "official_identity_status_0262") return owned;
      if (cmd === "official_identity_texture_0262") return result;
      throw Error(cmd);
    },
  );
  await assert.rejects(client.selectCape("not-owned"), /не принадлежит/);
  await assert.rejects(client.selectCape("../../other"), /не принадлежит/);
  assert.equal(
    calls.some((x) => x.cmd === "official_identity_texture_0262"),
    false,
  );
  assert.equal((await client.selectCape("owned")).capes[0].state, "ACTIVE");
  result = owned;
  await assert.rejects(client.selectCape("owned"), /не подтвердил/);
});

test("В версии 0.39.5 ответ нативной записи должен сохранять проверенный UUID Minecraft", async () => {
  const client = new OfficialMinecraftClient0257(
    "https://backend.example",
    "access",
    "sid",
    async (cmd) =>
      cmd === "official_identity_status_0262"
        ? profile
        : { ...profile, id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
  );
  await assert.rejects(client.resetSkin(), /другой UUID/);
});

test("Версия 0.39.5 не сообщает об удалении плаща, пока Minecraft считает его активным", async () => {
  const p = { ...profile, capes: [{ id: "cape", state: "ACTIVE", url: "" }] };
  const client = new OfficialMinecraftClient0257(
    "https://backend.example",
    "access",
    "sid",
    async () => p,
  );
  await assert.rejects(client.resetCape(), /не подтвердил/);
});

test("Версия 0.39.5 не применяет результат старой учётной записи при переключении аккаунта во время операции с текстурой", async () => {
  let release;
  const pending = new Promise((resolve) => (release = resolve));
  const client = new OfficialMinecraftClient0257(
    "https://backend.example",
    "access",
    "sid",
    async (cmd) => {
      if (cmd === "official_identity_status_0262") return profile;
      if (cmd === "official_identity_texture_0262") return pending;
      if (cmd === "official_identity_select_0267")
        return { ...profile, id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" };
      throw Error(cmd);
    },
  );
  const attempt = client.resetSkin();
  await new Promise((resolve) => setImmediate(resolve));
  await client.selectAccount("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  release(profile);
  await assert.rejects(attempt, /аккаунт изменился/);
});

test("Версия 0.39.5 проверяет размеры и модель PNG до передачи байтов через нативный IPC", async () => {
  const png = (w, h) => {
    const bytes = Buffer.alloc(33);
    Buffer.from("89504e470d0a1a0a", "hex").copy(bytes, 0);
    bytes.writeUInt32BE(13, 8);
    bytes.write("IHDR", 12);
    bytes.writeUInt32BE(w, 16);
    bytes.writeUInt32BE(h, 20);
    return new File([bytes], "skin.png", { type: "image/png" });
  };
  const calls = [];
  const ready = {
    ...profile,
    skins: [{ id: "skin", state: "ACTIVE", url: "", variant: "SLIM" }],
  };
  const client = new OfficialMinecraftClient0257(
    "https://backend.example",
    "access",
    "sid",
    async (cmd, args) => {
      calls.push(cmd);
      return cmd === "official_identity_status_0262" ? profile : ready;
    },
  );
  await assert.rejects(client.uploadSkin(png(128, 128), "slim"), /64×64/);
  await assert.rejects(client.uploadSkin(png(64, 32), "slim"), /64×64/);
  assert.equal(calls.length, 0);
  let percent = 0;
  assert.equal(
    (await client.uploadSkin(png(64, 64), "slim", (p) => (percent = p)))
      .skins[0].variant,
    "SLIM",
  );
  assert.equal(percent, 100);
  assert.equal(
    calls.filter((c) => c === "official_identity_texture_0262").length,
    1,
  );
});

test("Версия 0.39.5 после отмены серверной записи не должна ошибочно сообщать, что изменение откачено", async () => {
  const ctrl = new AbortController();
  const bytes = Buffer.alloc(33);
  Buffer.from("89504e470d0a1a0a", "hex").copy(bytes, 0);
  bytes.writeUInt32BE(13, 8);
  bytes.write("IHDR", 12);
  bytes.writeUInt32BE(64, 16);
  bytes.writeUInt32BE(64, 20);
  const ready = {
    ...profile,
    skins: [{ id: "new", state: "ACTIVE", url: "", variant: "CLASSIC" }],
  };
  const client = new OfficialMinecraftClient0257(
    "https://backend.example",
    "access",
    "sid",
    async (cmd) => {
      if (cmd === "official_identity_status_0262") return profile;
      ctrl.abort();
      return ready;
    },
  );
  const actual = await client.uploadSkin(
    new File([bytes], "skin.png", { type: "image/png" }),
    "classic",
    undefined,
    ctrl.signal,
  );
  assert.equal(actual.skins[0].id, "new");
});

test("Версия 0.39.6 передаёт операциям хранилища проверенный контекст Launcher вместо непривязанного SID", async () => {
  const received = [];
  const launcherToken = "bearer-live-0396";
  const client = new OfficialMinecraftClient0257(
    "https://backend.example",
    launcherToken,
    "sid-0396",
    async (command, args) => {
      received.push({ command, args });
      if (command === "official_identity_accounts_0267") return [];
      if (command === "official_identity_logout_0267") return;
      if (command === "official_identity_status_0262") return null;
      if (command === "official_identity_disconnect_0262") return;
      throw Error(command);
    },
  );
  assert.deepEqual(await client.accounts(), []);
  await client.logout(profile.id);
  await client.disconnect();
  const protectedCalls = received.filter((r) =>
    [
      "official_identity_accounts_0267",
      "official_identity_logout_0267",
      "official_identity_disconnect_0262",
    ].includes(r.command),
  );
  assert.equal(protectedCalls.length, 3);
  for (const { args } of protectedCalls) {
    assert.deepEqual(args.context, {
      backendUrl: "https://backend.example",
      launcherToken,
      launcherSessionId: "sid-0396",
    });
    assert.equal(args.launcherSessionId, undefined);
    assert.equal(args.backendUrl, undefined);
    assert.ok(!JSON.stringify(args).includes("minecraft_token"));
  }
});
