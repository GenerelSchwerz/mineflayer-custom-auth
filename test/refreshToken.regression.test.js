const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { Authflow } = require("prismarine-auth");
const { buildLivePatchedManager, getAccessTokenFromRefreshToken } = require("../dist/tokenAccess");

test("refresh-only seed is expired and preserves subsequently rotated tokens", async () => {
  let cached = {};
  const manager = { cache: { getCached: async () => cached } };
  buildLivePatchedManager(manager, { refreshToken: "fake-refresh" });
  const seeded = await manager.cache.getCached();
  assert.equal(seeded.token.access_token, undefined);
  assert.equal(seeded.token.expires_in, 0);
  cached = { token: { access_token: "new-access", refresh_token: "rotated", obtainedOn: 1, expires_in: 3600 } };
  assert.deepEqual(await manager.cache.getCached(), cached);
});

test("refresh-only seed cannot reuse an unrelated cached access token", async () => {
  const manager = { cache: { getCached: async () => ({ token: { access_token: "stale" } }) } };
  buildLivePatchedManager(manager, { refreshToken: "fake-refresh" });
  assert.equal((await manager.cache.getCached()).token.access_token, undefined);
});

test("standalone refresh exchanges before Xbox and exposes OAuth failures without device login", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "refresh-regression-"));
  const originalFetch = global.fetch;
  const originalJava = Authflow.prototype.getMinecraftJavaToken;
  let reject = false;
  let requests = 0;
  let javaCalls = 0;
  global.fetch = async (url, init) => {
    requests++;
    assert.match(String(url), /oauth20_token/);
    const form = new URLSearchParams(init.body);
    assert.equal(form.get("grant_type"), "refresh_token");
    assert.equal(form.get("refresh_token"), "fake-refresh");
    assert.equal(form.get("client_id"), "test-client");
    return new Response(JSON.stringify(reject ? { error: "invalid_grant" } : {
      access_token: "microsoft-access", refresh_token: "rotated", expires_in: 3600,
    }), { status: reject ? 400 : 200, statusText: reject ? "Bad Request" : "OK", headers: { "Content-Type": "application/json" } });
  };
  Authflow.prototype.getMinecraftJavaToken = async function () {
    javaCalls++;
    const cached = await this.msa.cache.getCached();
    assert.equal(cached.token.access_token, "microsoft-access");
    assert.equal(cached.token.refresh_token, "rotated");
    await assert.rejects(this.msa.authDeviceCode(), /sign in again/);
    return { token: "fake-minecraft", profile: { name: "Test", id: "test-id" } };
  };
  try {
    const result = await getAccessTokenFromRefreshToken("  fake-refresh  ", { profilesFolder: directory, authTitle: "test-client" });
    assert.equal(result.username, "Test");
    assert.equal(result.refreshToken, "rotated");
    reject = true;
    await assert.rejects(getAccessTokenFromRefreshToken("fake-refresh", { profilesFolder: directory, authTitle: "test-client" }), /Microsoft OAuth refresh failed/);
    assert.equal(requests, 2);
    assert.equal(javaCalls, 1);
    await assert.rejects(getAccessTokenFromRefreshToken("  "), /valid refresh token/);
    assert.equal(requests, 2);
  } finally {
    global.fetch = originalFetch;
    Authflow.prototype.getMinecraftJavaToken = originalJava;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

function runCli(args, mock) {
  const script = path.join(__dirname, "testRefreshToken.js");
  return spawnSync(process.execPath, ["-e", `
    const Module = require('node:module');
    const load = Module._load;
    Module._load = function(name, parent, ...rest) {
      if (name === '../dist' && parent.filename === ${JSON.stringify(script)}) return (${mock});
      return load.call(this, name, parent, ...rest);
    };
    process.argv = ['node', ${JSON.stringify(script)}, ...${JSON.stringify(args)}];
    require(${JSON.stringify(script)}).main().catch(error => {
      console.error(error.message);
      process.exitCode = 1;
    });
  `], { encoding: "utf8", timeout: 5000 });
}

function mockDirectRequests(t, handler) {
  const { EventEmitter } = require('node:events');
  t.mock.method(require('node:https'), 'request', (url, options, callback) => {
    const req = new EventEmitter();
    req.setTimeout = () => req;
    req.end = body => queueMicrotask(() => {
      try {
        const reply = handler(new URL(url), options, body);
        const response = new EventEmitter();
        response.statusCode = reply.status || 200;
        response.setEncoding = () => {};
        callback(response);
        response.emit('data', JSON.stringify(reply.data));
        response.emit('end');
      } catch (error) { req.emit('error', error); }
    });
    return req;
  });
}

test("token-only OAuth uses the original client and direct Xbox exchange without title/device auth", async t => {
  const requests = [];
  mockDirectRequests(t, (url, options, body) => {
    requests.push(url.hostname);
    if (url.hostname === 'login.live.com') {
      const form = new URLSearchParams(body);
      assert.equal(form.get('client_id'), '00000000402b5328');
      assert.equal(form.get('grant_type'), 'refresh_token');
      assert.equal(form.get('refresh_token'), 'M.C.synthetic.MsaArtifacts.token$');
      assert.equal(form.get('redirect_uri'), 'https://login.live.com/oauth20_desktop.srf');
      return { data: { access_token: 'ms-access', refresh_token: 'rotated' } };
    }
    if (url.hostname === 'user.auth.xboxlive.com') {
      assert.equal(JSON.parse(body).Properties.RpsTicket, 't=ms-access');
      return { data: { Token: 'xbl', DisplayClaims: { xui: [{ uhs: 'user-hash' }] } } };
    }
    if (url.hostname === 'xsts.auth.xboxlive.com') {
      assert.deepEqual(JSON.parse(body).Properties, { SandboxId: 'RETAIL', UserTokens: ['xbl'] });
      return { data: { Token: 'xsts' } };
    }
    if (url.pathname === '/authentication/login_with_xbox') {
      assert.equal(JSON.parse(body).identityToken, 'XBL3.0 x=user-hash;xsts');
      return { data: { access_token: 'minecraft-token', expires_in: 86400 } };
    }
    assert.equal(url.pathname, '/minecraft/profile');
    assert.equal(options.headers.Authorization, 'Bearer minecraft-token');
    return { data: { name: 'TokenOnly', id: 'profile-id' } };
  });
  const result = await getAccessTokenFromRefreshToken('RefreshToken: "M.C.synthetic.MsaArtifacts.token$"');
  assert.equal(result.username, 'TokenOnly');
  assert.equal(result.uuid, 'profile-id');
  assert.equal(result.refreshToken, 'rotated');
  assert.deepEqual(requests, ['login.live.com', 'user.auth.xboxlive.com', 'xsts.auth.xboxlive.com', 'api.minecraftservices.com', 'api.minecraftservices.com']);
  await assert.rejects(getAccessTokenFromRefreshToken('RefreshToken: '), /valid refresh token/);
  assert.equal(requests.length, 5);
});

test('direct OAuth failure is redacted and stops before Xbox authentication', async t => {
  let requests = 0;
  mockDirectRequests(t, () => {
    requests++;
    return { status: 400, data: { error: 'invalid_grant', error_description: 'Rejected private-refresh-value' } };
  });
  await assert.rejects(getAccessTokenFromRefreshToken('private-refresh-value'), error => {
    assert.match(error.message, /Microsoft OAuth refresh failed with HTTP 400/);
    assert.doesNotMatch(error.message, /private-refresh-value/);
    return true;
  });
  assert.equal(requests, 1);
});

test('real Mineflayer auth uses the supplied refresh token, rotated token and matching profile', { timeout: 15000 }, async t => {
  const { createBot } = require('../dist');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'mineflayer-refresh-'));
  t.after(() => {
    assert.equal(path.dirname(path.resolve(directory)), path.resolve(os.tmpdir()));
    assert.ok(path.basename(directory).startsWith('mineflayer-refresh-'));
    fs.rmSync(directory, { recursive: true, force: true });
  });
  const inputs = [];
  let account;
  let javaToken;
  const profileRequests = [];
  mockDirectRequests(t, (url, options, body) => {
    if (url.hostname === 'login.live.com') {
      const form = new URLSearchParams(body);
      assert.equal(form.get('client_id'), '00000000402b5328');
      account = form.get('refresh_token');
      inputs.push(account);
      javaToken = 'eyJhbGciOiJub25lIn0.' + Buffer.from(JSON.stringify({
        exp: Math.floor(Date.now() / 1000) + 3600,
        pfd: [{ type: 'mc', name: account, id: '12345678901234567890123456789012' }],
      })).toString('base64url') + '.signature';
      return { data: { access_token: 'ms-access', refresh_token: account + '-rotated' } };
    }
    if (url.hostname === 'user.auth.xboxlive.com') {
      assert.equal(JSON.parse(body).Properties.RpsTicket, 't=ms-access');
      return { data: { Token: 'xbl', DisplayClaims: { xui: [{ uhs: 'user-hash' }] } } };
    }
    if (url.hostname === 'xsts.auth.xboxlive.com') {
      assert.deepEqual(JSON.parse(body).Properties, { SandboxId: 'RETAIL', UserTokens: ['xbl'] });
      return { data: { Token: 'xsts' } };
    }
    assert.equal(url.href, 'https://api.minecraftservices.com/authentication/login_with_xbox');
    return { data: { access_token: javaToken, expires_in: 3600 } };
  });
  t.mock.method(global, 'fetch', async (url, options) => {
    assert.equal(String(url), 'https://api.minecraftservices.com/minecraft/profile');
    assert.equal(options.headers.Authorization, 'Bearer ' + javaToken);
    profileRequests.push(account);
    return new Response(JSON.stringify({ id: '12345678901234567890123456789012', name: account }), {
      headers: { 'Content-Type': 'application/json' },
    });
  });
  for (const refreshToken of ['FirstAccount', 'SecondAccount']) {
    let bot;
    const client = await new Promise((resolve, reject) => {
      bot = createBot({
        host: 'localhost', username: 'same-user', refreshToken,
        profilesFolder: directory, version: '1.21.4',
        disableChatSigning: true, loadInternalPlugins: false,
        hideErrors: true,
        connect: resolve,
      });
      bot.on('error', reject);
    });
    assert.equal(client, bot._client);
    assert.equal(client.session.accessToken, javaToken);
    assert.equal(client.session.selectedProfile.name, refreshToken);
    assert.equal(client.username, refreshToken);
    assert.equal((await client.authflow.msa.cache.getCached()).token.refresh_token, refreshToken + '-rotated');
    bot.end();
  }
  assert.deepEqual(inputs, ['FirstAccount', 'SecondAccount']);
  assert.deepEqual(profileRequests, inputs);
});

test("CLI reports a pending exchange timeout instead of silently exiting", () => {
  const result = runCli(["fake-refresh", "--timeout", "50"], `{ getAccessTokenFromRefreshToken: () => new Promise(() => {}) }`);
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /timed out after 50 ms/);
});

test("CLI forwards the chosen client and propagates a redacted failure", () => {
  const result = runCli(["fake-refresh", "--client-id", "test-client"], `{
    getAccessTokenFromRefreshToken: async (token, options) => {
      if (options.authTitle !== 'test-client') throw new Error('wrong client');
      throw new Error('OAuth rejected ' + token);
    }
  }`);
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /OAuth rejected \[redacted\]/);
  assert.doesNotMatch(result.stdout + result.stderr, /fake-refresh/);
});

test("CLI distinguishes cookie files from plain refresh token txt files", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "refresh-cli-"));
  try {
    const tokenFile = path.join(directory, "token.txt");
    const cookieFile = path.join(directory, "cookies.txt");
    fs.writeFileSync(tokenFile, "fake-refresh");
    fs.writeFileSync(cookieFile, ".example.test\tTRUE\t/\tTRUE\t1800000000\tplaceholder\tdummy\n");
    const token = runCli([tokenFile], `{
      getAccessTokenFromRefreshToken: async token => {
        if (token !== 'fake-refresh') throw new Error('wrong token');
        return { username: 'RefreshTest', accessToken: 'secret-result' };
      }
    }`);
    assert.equal(token.status, 0, token.stderr);
    assert.match(token.stdout, /RefreshTest/);
    assert.doesNotMatch(token.stdout, /secret-result/);
    const cookie = runCli([cookieFile], `{
      getAccessToken: async input => {
        if (input.cookieFile !== ${JSON.stringify(cookieFile)}) throw new Error('wrong cookie path');
        return { username: 'CookieTest' };
      }
    }`);
    assert.equal(cookie.status, 0, cookie.stderr);
    assert.match(cookie.stdout, /CookieTest/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
