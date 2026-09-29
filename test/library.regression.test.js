const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter, once } = require('node:events');
const mineflayer = require('mineflayer');
const microsoftAuth = require('minecraft-protocol/src/client/microsoftAuth');
const browserless = require('../dist/cookies/browserless');
const browser = require('../dist/cookies/browser');
const msauth = require('../dist/cookies/msauth');
const unified = require('../dist/unified');
const { createBot, cookie, createCookieAuthenticator, BrowserlessCookieAuthenticator, BrowserCookieAuthenticator } = require('../dist');
const { generateCacheFileName } = require('../dist/utils');

function tempDirectory(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-library-'));
  t.after(() => {
    assert.equal(path.dirname(path.resolve(directory)), path.resolve(os.tmpdir()));
    assert.ok(path.basename(directory).startsWith('auth-library-'));
    fs.rmSync(directory, { recursive: true, force: true });
  });
  return directory;
}

function jwt(name, expiresIn = 3600) {
  return 'eyJhbGciOiJub25lIn0.' + Buffer.from(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + expiresIn, pfd: [{ type: 'mc', name, id: name + '-id' }] })).toString('base64url') + '.signature';
}

function cookieData(value) { return [{ name: '__Host-MSAAUTHP', value, domain: 'login.live.com' }]; }

function mockBotConnection(t) {
  t.mock.method(mineflayer, 'createBot', options => {
    const bot = new EventEmitter();
    bot.options = options;
    queueMicrotask(() => options.auth(bot, options));
    return bot;
  });
  t.mock.method(microsoftAuth, 'authenticate', async (client, options) => {
    const cached = await client.authflow.mca.cache.getCached();
    client.emit('authenticated', cached.mca.access_token, options);
  });
}

test('original createBot cookie API uses new cookie flow and forwards the resulting token', async t => {
  mockBotConnection(t);
  const profilesFolder = tempDirectory(t);
  let exchanges = 0;
  const expectedToken = jwt('OriginalAPI');
  t.mock.method(msauth, 'getAccessTokenFromMsauthCookie', async (value, options) => {
    exchanges++;
    assert.equal(value, '11-M.C.test$');
    assert.equal(options.timeout, 1200);
    return { accessToken: expectedToken, uuid: 'test-id', username: 'OriginalAPI' };
  });
  const source = cookie.parseCookies('login.live.com\tFALSE\t/\tTRUE\t0\t__Host-MSAAUTHP\t11-M.C.test$');
  const options = { username: 'account', host: 'localhost', auth: 'cookies', profilesFolder, cookieOptions: { cookies: source, timeout: 1200 } };
  const bot = createBot(options);
  const [token] = await once(bot, 'authenticated');
  assert.equal(token, expectedToken);
  assert.equal(exchanges, 1);
  assert.equal(options.auth, 'cookies');
  assert.equal(options.javaAccessToken, undefined);
});

test('changed cookie contents for the same username do not reuse the prior account', async t => {
  const directory = tempDirectory(t);
  let exchanges = 0;
  t.mock.method(browserless, 'authenticateWithBrowserlessCookies', async cookies => {
    exchanges++;
    return { accessToken: jwt(cookies[0].value), username: cookies[0].value };
  });
  const auth = new BrowserlessCookieAuthenticator(directory);
  const a = await auth.processAccount('same-user', cookieData('First'));
  const cached = await auth.processAccount('same-user', cookieData('First'));
  const b = await auth.processAccount('same-user', cookieData('Second'));
  assert.equal(a.fromCache, false);
  assert.equal(cached.fromCache, true);
  assert.equal(b.fromCache, false);
  assert.notEqual(a.token, b.token);
  assert.equal(exchanges, 2);
  const cachedFile = JSON.parse(fs.readFileSync(generateCacheFileName(directory, 'mca', 'same-user'), 'utf8'));
  assert.ok(cachedFile.mca.expires_in <= 3600);
  assert.match(cachedFile.cookie_input_hash, /^[a-f0-9]{64}$/);
});

test('browser cookie cache also rereads an edited file before selecting an account', async t => {
  const directory = tempDirectory(t);
  const file = path.join(directory, 'cookies.txt');
  let exchanges = 0;
  t.mock.method(browser, 'authenticateWithBrowserCookies', async cookies => {
    exchanges++;
    return { accessToken: jwt(cookies[0].value) };
  });
  const auth = new BrowserCookieAuthenticator(directory);
  fs.writeFileSync(file, 'MSPAuth=First');
  const a = await auth.processAccount('same-user', file);
  fs.writeFileSync(file, 'MSPAuth=Second');
  const b = await auth.processAccount('same-user', file);
  assert.notEqual(a.token, b.token);
  assert.equal(exchanges, 2);
});

test('legacy username-only cache and expired tokens are not reused', async t => {
  const directory = tempDirectory(t);
  const cache = generateCacheFileName(directory, 'mca', 'same-user');
  fs.writeFileSync(cache, JSON.stringify({ cookie: true, mca: { access_token: jwt('Old'), expires_in: 86400, obtainedOn: Date.now() } }));
  let exchanges = 0;
  t.mock.method(browserless, 'authenticateWithBrowserlessCookies', async () => {
    exchanges++;
    return { accessToken: jwt('Expired', -60) };
  });
  const auth = new BrowserlessCookieAuthenticator(directory);
  assert.equal((await auth.processAccount('same-user', cookieData('Same'))).fromCache, false);
  assert.equal((await auth.processAccount('same-user', cookieData('Same'))).fromCache, false);
  assert.equal(exchanges, 2);
});

test('auto falls back to browser while forced browserless never opens it', async t => {
  const directory = tempDirectory(t);
  t.mock.method(browserless, 'authenticateWithBrowserlessCookies', async () => { throw new Error('Silent auth failed'); });
  let browsers = 0;
  t.mock.method(browser, 'authenticateWithBrowserCookies', async () => { browsers++; return { accessToken: jwt('Browser') }; });
  const forced = createCookieAuthenticator('browserless', directory);
  assert.equal((await forced.processAccount('forced', cookieData('Same'))).success, false);
  assert.equal(browsers, 0);
  const auto = createCookieAuthenticator('auto', directory);
  assert.equal((await auto.processAccount('auto', cookieData('Same'))).success, true);
  assert.equal(browsers, 1);
  await assert.rejects(unified.getAccessToken({ cookies: cookieData('Same') }, { authMethod: 'browserless' }), /Silent auth failed/);
  assert.equal(browsers, 1);
});

test('createBot refresh aliases use the fixed exchange and inject the new Java token', async t => {
  mockBotConnection(t);
  const profilesFolder = tempDirectory(t);
  const inputs = [];
  t.mock.method(unified, 'getAccessToken', async (input, options) => {
    inputs.push(input.refreshToken);
    assert.equal(options.authTitle, 'issued-by-client');
    return { accessToken: jwt(input.refreshToken) };
  });
  const first = createBot({ username: 'same-user', host: 'localhost', auth: 'refreshToken', refreshToken: 'First', authTitle: 'issued-by-client', flow: 'live', profilesFolder });
  const [a] = await once(first, 'authenticated');
  const second = createBot({ username: 'same-user', host: 'localhost', liveRefreshToken: 'Second', authTitle: 'issued-by-client', flow: 'live', profilesFolder });
  const [b] = await once(second, 'authenticated');
  assert.deepEqual(inputs, ['First', 'Second']);
  assert.notEqual(a, b);
});

test('custom auth rejection is delivered as a bot error event', async t => {
  mockBotConnection(t);
  t.mock.method(unified, 'getAccessToken', async () => { throw new Error('Refresh rejected'); });
  const bot = createBot({ username: 'test', host: 'localhost', auth: 'refreshToken', refreshToken: 'fake', profilesFolder: tempDirectory(t) });
  const [error] = await once(bot, 'error');
  assert.equal(error.message, 'Refresh rejected');
});

test('a custom client ID works without separately supplying flow or device type', async t => {
  mockBotConnection(t);
  const token = jwt('CustomClient');
  t.mock.method(unified, 'getAccessToken', async (input, options) => {
    assert.equal(options.authTitle, 'custom-client');
    return { accessToken: token };
  });
  const bot = createBot({ username: 'test', host: 'localhost', auth: 'refreshToken', refreshToken: 'fake', authTitle: 'custom-client', profilesFolder: tempDirectory(t) });
  assert.equal((await once(bot, 'authenticated'))[0], token);
  assert.equal(bot.authflow.options.flow, 'live');
  assert.equal(bot.authflow.options.deviceType, 'Nintendo');
  assert.equal(bot.authflow.options.authTitle, 'custom-client');
});

test('provided live/sisu flow and device type are retained when using the default client', async t => {
  mockBotConnection(t);
  const bot = createBot({ username: 'test', host: 'localhost', auth: 'accessToken', javaAccessToken: jwt('CustomDevice'), flow: 'sisu', deviceType: 'Win32', profilesFolder: tempDirectory(t) });
  await once(bot, 'authenticated');
  assert.equal(bot.authflow.options.flow, 'sisu');
  assert.equal(bot.authflow.options.deviceType, 'Win32');
});

test('runnable examples accept credentials and server options without connecting on import', t => {
  let calls = 0;
  t.mock.method(mineflayer, 'createBot', options => {
    calls++;
    const bot = new EventEmitter();
    bot.options = options;
    return bot;
  });
  const refreshExample = require('../examples/refresh-token');
  const cookieExample = require('../examples/cookies');
  const accessExample = require('../examples/access-token');
  assert.equal(calls, 0);
  const refresh = refreshExample.main({ REFRESH_TOKEN: 'only-token' }, ['localhost', '25566']);
  assert.equal(refresh.options.liveRefreshToken, 'only-token');
  assert.equal(refresh.options.authTitle, undefined);
  assert.equal(refresh.options.port, 25566);
  const file = path.join(tempDirectory(t), 'cookies.txt');
  fs.writeFileSync(file, 'MSPAuth=example');
  const cookies = cookieExample.main([file]);
  assert.equal(cookies.options.cookieOptions.cookieFile, file);
  assert.equal(cookies.options.cookieOptions.authMethod, 'auto');
  const access = accessExample.main({ MINECRAFT_ACCESS_TOKEN: 'java-token' }, []);
  assert.equal(access.options.javaAccessToken, 'java-token');
  assert.equal(calls, 3);
  assert.throws(() => refreshExample.main({}, []), /Set REFRESH_TOKEN/);
  assert.throws(() => cookieExample.main([]), /cookie file must exist/);
  assert.throws(() => accessExample.main({}, []), /MINECRAFT_ACCESS_TOKEN/);
  assert.throws(() => refreshExample.main({ REFRESH_TOKEN: 'only-token' }, ['localhost', '-1']), /Server port/);
  assert.equal(calls, 3);
});

test('original accessToken API and ordinary Mineflayer options remain supported', async t => {
  mockBotConnection(t);
  const accessToken = jwt('Direct');
  const bot = createBot({ username: 'test', host: 'localhost', auth: 'accessToken', javaAccessToken: accessToken, profilesFolder: tempDirectory(t) });
  assert.equal((await once(bot, 'authenticated'))[0], accessToken);
  t.mock.method(mineflayer, 'createBot', options => options);
  const customAuth = () => {};
  assert.equal(createBot({ username: 'test', auth: customAuth }).auth, customAuth);
  assert.equal(createBot({ username: 'test', auth: 'offline' }).auth, 'offline');
});
