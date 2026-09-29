const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const https = require('node:https');
const { EventEmitter } = require('node:events');
const { spawnSync } = require('node:child_process');
const { loadConfiguration } = require('../refresh_single');
const { getAccessToken } = require('../dist/unified');
const oauth = require('../dist/tokenAccess');
const msauth = require('../dist/cookies/msauth');
const browser = require('../dist/cookies/browser');
const browserless = require('../dist/cookies/browserless');

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'merged-auth-'));
  t.after(() => {
    assert.equal(path.dirname(path.resolve(directory)), path.resolve(os.tmpdir()));
    assert.ok(path.basename(directory).startsWith('merged-auth-'));
    fs.rmSync(directory, { recursive: true, force: true });
  });
  return (name, content) => {
    const file = path.join(directory, name);
    fs.writeFileSync(file, content);
    return file;
  };
}

test('saved env changes override inherited values and produce different fingerprints', t => {
  const write = fixture(t);
  const env = write('.env', 'REFRESH_TOKEN=M.R-first');
  const a = loadConfiguration(['--env', env], { REFRESH_TOKEN: 'stale' });
  write('.env', 'REFRESH_TOKEN="M.R-second" # updated');
  const b = loadConfiguration(['--env', env], { REFRESH_TOKEN: 'stale' });
  assert.equal(a.input, 'M.R-first');
  assert.equal(a.inputType, 'refresh-token');
  assert.equal(b.input, 'M.R-second');
  assert.notEqual(a.fingerprint, b.fingerprint);
  assert.match(b.source, /REFRESH_TOKEN/);
  assert.equal(loadConfiguration(['explicit', '--env', env], {}).input, 'explicit');
  write('.env', 'REFRESH_TOKEN=');
  assert.throws(() => loadConfiguration(['--env', env], { REFRESH_TOKEN: 'stale' }), /No input/);
});

test('ambiguous or duplicate env credentials fail instead of silently selecting old input', t => {
  const write = fixture(t);
  const env = write('.env', 'REFRESH_TOKEN=one\nREFRESH_TOKEN=two');
  assert.throws(() => loadConfiguration(['--env', env], {}), /Duplicate REFRESH_TOKEN/);
  write('.env', 'REFRESH_TOKEN=one\nMSAAUTH_COOKIE=two');
  assert.throws(() => loadConfiguration(['--env', env], {}), /Set only one/);
  write('.env', 'MSAAUTH_COOKIE=M.C.synthetic.MsaArtifacts.new');
  assert.equal(loadConfiguration(['--env', env], { REFRESH_TOKEN: 'old' }).selectedKey, 'MSAAUTH_COOKIE');
});

test('env cookie paths are relative to env file and reflect changed file contents', t => {
  const write = fixture(t);
  const file = write('cookies.txt', 'first');
  const env = write('.env', 'COOKIE_FILE=./cookies.txt');
  const a = loadConfiguration(['--env', env, '--check-config'], {});
  assert.equal(a.input, file);
  assert.equal(a.checkConfig, true);
  write('cookies.txt', 'second');
  assert.notEqual(a.fingerprint, loadConfiguration(['--env', env], {}).fingerprint);
  assert.throws(() => loadConfiguration(['./missing-cookie.txt', '--env', env], {}), /does not exist/);
});

test('unified routing distinguishes OAuth, session cookies, token files and cookie exports', async t => {
  const write = fixture(t);
  const calls = [];
  t.mock.method(oauth, 'getAccessTokenFromRefreshToken', async input => { calls.push(['oauth', input]); return {}; });
  t.mock.method(msauth, 'getAccessTokenFromMsauthCookie', async input => { calls.push(['session', input]); return { accessToken: 'mock-minecraft' }; });
  const originalBrowserless = browserless.authenticateWithBrowserlessCookies;
  t.mock.method(browserless, 'authenticateWithBrowserlessCookies', async (cookies, ...args) => {
    return cookies.some(c => c.name === '__Host-MSAAUTHP') ? originalBrowserless(cookies, ...args) : undefined;
  });
  t.mock.method(browser, 'getAccessTokenFromBrowser', async input => { calls.push(['browser', input]); return {}; });
  const session = 'M.C.synthetic.MsaArtifacts.account';
  await getAccessToken(write('refresh.txt', 'M.R-actual-refresh'));
  assert.deepEqual(calls.pop(), ['oauth', 'M.R-actual-refresh']);
  await getAccessToken(write('refresh.json', JSON.stringify({ refresh_token: 'M.R-json' })));
  assert.deepEqual(calls.pop(), ['oauth', 'M.R-json']);
  await getAccessToken(session);
  assert.deepEqual(calls.pop(), ['oauth', session]);
  await getAccessToken({ refreshToken: session });
  assert.equal(calls.pop()[0], 'oauth');
  await getAccessToken({ refreshToken: `11-${session}$` });
  assert.deepEqual(calls.pop(), ['oauth', `11-${session}$`]);
  await getAccessToken(write('named-refresh.json', JSON.stringify({ refresh_token: session })));
  assert.deepEqual(calls.pop(), ['oauth', session]);
  await getAccessToken({ msauthCookie: session });
  assert.equal(calls.pop()[0], 'session');
  await getAccessToken(`11-${session}$`);
  assert.equal(calls.pop()[0], 'session');
  for (const content of [
    `#HttpOnly_login.live.com\tFALSE\t/\tTRUE\t0\t__Host-MSAAUTHP\t11-${session}$`,
    JSON.stringify([{ name: '__Host-MSAAUTHP', value: `11-${session}$`, domain: 'login.live.com' }]),
    `__Host-MSAAUTHP=11-${session}$`,
  ]) {
    await getAccessToken(write('cookies.txt', content));
    assert.deepEqual(calls.pop(), ['session', `11-${session}$`]);
  }
  await getAccessToken([{ name: 'MSPAuth', value: 'example', domain: 'login.live.com' }]);
  assert.equal(calls.pop()[0], 'browser');
  await getAccessToken({ cookies: `__Host-MSAAUTHP=11-${session}$` }, { authMethod: 'browser' });
  assert.equal(calls.pop()[0], 'browser');
  await assert.rejects(getAccessToken(write('empty.txt', '')), /empty/);
  await assert.rejects(getAccessToken('./does-not-exist.txt'), /does not exist/);
  await assert.rejects(getAccessToken({ cookieFile: './does-not-exist.txt' }), /does not exist/);
  await assert.rejects(getAccessToken(write('invalid.json', '{}')), /single token record/);
  assert.equal(calls.length, 0);
});

function runCli(args, mock) {
  const script = path.join(__dirname, '..', 'refresh_single.js');
  return spawnSync(process.execPath, ['-e', `
    const Module = require('node:module');
    const load = Module._load;
    Module._load = function(name, parent, ...rest) {
      if (name === './dist' && parent.filename === ${JSON.stringify(script)}) return (${mock});
      return load.call(this, name, parent, ...rest);
    };
    require(${JSON.stringify(script)}).main(${JSON.stringify(args)}).catch(error => {
      console.error(error.message); process.exitCode = 1;
    });
  `], { encoding: 'utf8', timeout: 5000 });
}

test('merged CLI handles saved changes across processes, hides tokens, and honors check-config', t => {
  const write = fixture(t);
  const env = write('.env', 'REFRESH_TOKEN=first-secret');
  const mock = `{ getAccessTokenFromRefreshToken: async input => ({ username: input === 'first-secret' ? 'First' : 'Second', accessToken: 'result-secret' }) }`;
  const first = runCli(['--env', env], mock);
  assert.equal(first.status, 0, first.stderr);
  assert.match(first.stdout, /First/);
  assert.doesNotMatch(first.stdout, /first-secret|result-secret/);
  write('.env', 'REFRESH_TOKEN=second-secret');
  const second = runCli(['--env', env, '--show-token'], mock);
  assert.equal(second.status, 0, second.stderr);
  assert.match(second.stdout, /Second/);
  assert.match(second.stdout, /result-secret/);
  const check = runCli(['--env', env, '--check-config'], `(() => { throw new Error('authentication library loaded'); })()`);
  assert.equal(check.status, 0, check.stderr);
  assert.match(check.stdout, /fingerprint/);
  const timed = runCli(['--env', env, '--timeout', '50'], `{ getAccessTokenFromRefreshToken: () => new Promise(() => {}) }`);
  assert.equal(timed.status, 1, timed.stderr);
  assert.match(timed.stderr, /timed out/);
});

test('only REFRESH_TOKEN is required; no input-type or client-id setting is needed', t => {
  const write = fixture(t);
  const env = write('.env', 'REFRESH_TOKEN=M.C.synthetic.MsaArtifacts.token$');
  const result = runCli(['--env', env], `{
    getAccessToken: async () => { throw new Error('unexpected auto detection'); },
    getAccessTokenFromMsauthCookie: async () => { throw new Error('unexpected cookie login'); },
    getAccessTokenFromRefreshToken: async token => {
      if (token !== 'M.C.synthetic.MsaArtifacts.token$') throw new Error('token changed');
      return { username: 'TokenOnly' };
    }
  }`);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /TokenOnly/);
  assert.match(result.stdout, /Input type: refresh-token/);
});

test('explicit OAuth input type bypasses session-cookie format guessing', t => {
  const write = fixture(t);
  const env = write('.env', 'REFRESH_TOKEN=M.C.synthetic.MsaArtifacts.token\nAUTH_INPUT_TYPE=refresh-token\nMICROSOFT_CLIENT_ID=original-client');
  const mock = `{
    getAccessToken: async () => { throw new Error('incorrect auto route'); },
    getAccessTokenFromRefreshToken: async (token, options) => {
      if (token !== 'M.C.synthetic.MsaArtifacts.token' || options.authTitle !== 'original-client') throw new Error('incorrect OAuth input');
      return { username: 'OAuthTest' };
    },
    getAccessTokenFromMsauthCookie: async () => ({ username: 'CookieTest' })
  }`;
  const oauth = runCli(['--env', env], mock);
  assert.equal(oauth.status, 0, oauth.stderr);
  assert.match(oauth.stdout, /OAuthTest/);
  const cookie = runCli(['--env', env, '--input-type', 'msauth-cookie'], mock);
  assert.equal(cookie.status, 0, cookie.stderr);
  assert.match(cookie.stdout, /CookieTest/);
  assert.throws(() => loadConfiguration(['--env', env, '--input-type', 'unknown'], {}), /Input type/);
});

function mockHttp(t, handler) {
  t.mock.method(https, 'request', (url, options, callback) => {
    const req = new EventEmitter();
    req.setTimeout = () => req;
    req.end = body => queueMicrotask(() => {
      try {
        const reply = handler(new URL(url), options, body ? JSON.parse(body) : undefined);
        const res = new EventEmitter();
        res.statusCode = reply.status ?? 200;
        res.headers = reply.headers ?? {};
        res.setEncoding = () => {};
        callback(res);
        res.emit('data', JSON.stringify(reply.data ?? {}));
        res.emit('end');
      } catch (error) { req.emit('error', error); }
    });
    return req;
  });
}

test('session-cookie exchange sends each new input and completes all four stages without cached identity', async t => {
  const cookies = [];
  let count = 0;
  mockHttp(t, (url, options, body) => {
    count++;
    if (url.hostname === 'login.live.com') {
      cookies.push(options.headers.Cookie);
      assert.equal(url.searchParams.get('client_id'), 'custom-client');
      return { status: 302, headers: { location: 'https://login.live.com/oauth20_desktop.srf#access_token=ms-token' } };
    }
    if (url.hostname === 'user.auth.xboxlive.com') {
      assert.equal(body.Properties.RpsTicket, 't=ms-token');
      return { data: { Token: 'xbl', DisplayClaims: { xui: [{ uhs: 'hash' }] } } };
    }
    if (url.hostname === 'xsts.auth.xboxlive.com') {
      assert.deepEqual(body.Properties.UserTokens, ['xbl']);
      return { data: { Token: 'xsts' } };
    }
    assert.equal(url.pathname, '/authentication/login_with_xbox');
    assert.equal(body.identityToken, 'XBL3.0 x=hash;xsts');
    const name = cookies.length === 1 ? 'First' : 'Second';
    return { data: { access_token: 'eyJhbGciOiJub25lIn0.' + Buffer.from(JSON.stringify({ pfd: [{ type: 'mc', name, id: name + '-id' }] })).toString('base64url') + '.signature', expires_in: 3600 } };
  });
  const first = await msauth.getAccessTokenFromMsauthCookie('M.C.first', { microsoftClientId: 'custom-client' });
  const second = await msauth.getAccessTokenFromMsauthCookie('11-M.C.second$', { microsoftClientId: 'custom-client' });
  assert.deepEqual(cookies, ['__Host-MSAAUTHP=11-M.C.first$', '__Host-MSAAUTHP=11-M.C.second$']);
  assert.equal(first.username, 'First');
  assert.equal(second.username, 'Second');
  assert.equal(second.uuid, 'Second-id');
  assert.equal(count, 8);
});

test('cookie authorization rejection stops before Xbox without exposing response secrets', async t => {
  let count = 0;
  mockHttp(t, () => { count++; return { status: 401, data: { secret: 'do-not-print' } }; });
  await assert.rejects(msauth.getAccessTokenFromMsauthCookie('M.C.fake'), error => {
    assert.match(error.message, /HTTP 401/);
    assert.doesNotMatch(error.message, /do-not-print|M.C.fake/);
    return true;
  });
  assert.equal(count, 1);
});
