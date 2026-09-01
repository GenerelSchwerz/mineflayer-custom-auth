'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const crypto = require('crypto');
const { URL, URLSearchParams } = require('url');

const CLIENT_ID = '00000000402b5328';
const REDIRECT_URI = 'https://login.live.com/oauth20_desktop.srf';
const DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
const CACHE_FILE = path.join(__dirname, 'cache', 'session-cache.json');

/**
 * Session cache helpers to avoid redundant network requests & HTTP 429 rate limits
 */
function getCacheHash(key) {
  return crypto.createHash('sha256').update(String(key).trim()).digest('hex').slice(0, 16);
}

function loadCache() {
  try {
    if (fs.existsSync(CACHE_FILE)) {
      return JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
    }
  } catch (_) {}
  return {};
}

function saveCache(cache) {
  try {
    const dir = path.dirname(CACHE_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(CACHE_FILE, JSON.stringify(cache, null, 2), 'utf8');
  } catch (_) {}
}

function getCachedSession(key) {
  const cache = loadCache();
  const hash = getCacheHash(key);
  const entry = cache[hash];
  if (entry && entry.accessToken && entry.expiresAt && entry.expiresAt > Date.now() + 5 * 60 * 1000) {
    return entry;
  }
  return null;
}

function setCachedSession(key, session, expiresInSec = 86400) {
  const cache = loadCache();
  const hash = getCacheHash(key);
  const expiresAt = Date.now() + (expiresInSec * 1000);
  cache[hash] = {
    ...session,
    cachedAt: Date.now(),
    expiresAt
  };
  saveCache(cache);
}

function clearCachedSession(key) {
  const cache = loadCache();
  const hash = getCacheHash(key);
  if (cache[hash]) {
    delete cache[hash];
    saveCache(cache);
  }
}

/**
 * Make an HTTP/HTTPS request with optional HTTP CONNECT proxy support
 */
function requestJson(targetUrl, { method = 'GET', headers = {}, body = null, timeout = 20000 } = {}, proxy = null) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(targetUrl);
    const isHttps = urlObj.protocol === 'https:';

    const reqHeaders = {
      'User-Agent': DEFAULT_USER_AGENT,
      ...headers
    };

    const reqOptions = {
      method,
      headers: reqHeaders,
      timeout
    };

    if (proxy && isHttps) {
      const proxyUrl = new URL(proxy.startsWith('http') ? proxy : `http://${proxy}`);
      const proxyReq = http.request({
        host: proxyUrl.hostname,
        port: proxyUrl.port || 8080,
        method: 'CONNECT',
        path: `${urlObj.hostname}:${urlObj.port || 443}`,
        headers: {
          Host: `${urlObj.hostname}:${urlObj.port || 443}`,
          ...(proxyUrl.username ? {
            'Proxy-Authorization': 'Basic ' + Buffer.from(`${decodeURIComponent(proxyUrl.username)}:${decodeURIComponent(proxyUrl.password || '')}`).toString('base64')
          } : {})
        }
      });

      proxyReq.on('connect', (res, socket) => {
        if (res.statusCode === 200) {
          reqOptions.socket = socket;
          reqOptions.agent = false;
          reqOptions.hostname = urlObj.hostname;
          reqOptions.port = urlObj.port || 443;
          reqOptions.path = urlObj.pathname + urlObj.search;

          const req = https.request(reqOptions, handleResponse);
          req.on('error', reject);
          req.on('timeout', () => {
            req.destroy(new Error(`Request timed out after ${timeout}ms`));
          });
          if (body) req.write(body);
          req.end();
        } else {
          reject(new Error(`Proxy CONNECT failed with HTTP status ${res.statusCode}`));
        }
      });

      proxyReq.on('error', reject);
      proxyReq.on('timeout', () => {
        proxyReq.destroy(new Error(`Proxy tunnel timed out after ${timeout}ms`));
      });
      proxyReq.end();
    } else {
      reqOptions.hostname = urlObj.hostname;
      reqOptions.port = urlObj.port || (isHttps ? 443 : 80);
      reqOptions.path = urlObj.pathname + urlObj.search;

      const lib = isHttps ? https : http;
      const req = lib.request(reqOptions, handleResponse);
      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy(new Error(`Request timed out after ${timeout}ms`));
      });
      if (body) req.write(body);
      req.end();
    }

    function handleResponse(res) {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            resolve(data);
          }
        } else if (res.statusCode === 429) {
          reject(new Error(`HTTP 429 Rate Limited: Mojang/Microsoft auth requests are being throttled. Please wait before retrying.`));
        } else {
          reject(new Error(`HTTP ${res.statusCode}: ${data}`));
        }
      });
    }
  });
}

/**
 * Converts Netscape cookie file to Minecraft JWT token
 */
async function cookieFileToJwt(filePath, proxy = null) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Cookie file not found: ${filePath}`);
  }
  const fileData = fs.readFileSync(filePath, 'utf8');
  return await cookiesToJwt(fileData, proxy);
}

/**
 * Converts Netscape cookies or cookie header string into Minecraft JWT token
 */
async function cookiesToJwt(cookieContent, proxy = null) {
  // Check session cache first!
  const cached = getCachedSession(cookieContent);
  if (cached) {
    return cached;
  }

  // Parse Netscape cookies into Cookie header string
  const cookieLines = cookieContent.split(/\r?\n/).filter(l => l.trim() && !l.startsWith('#'));
  const cookieHeader = cookieLines.map(l => {
    const p = l.split('\t');
    if (p.length >= 7) return `${p[5]}=${p[6]}`;
    return l;
  }).join('; ');

  const authUrl = `https://login.live.com/oauth20_authorize.srf?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=token&scope=service::user.auth.xboxlive.com::MBI_SSL`;

  let msAccessToken = null;

  try {
    msAccessToken = await new Promise((resolve, reject) => {
      const u = new URL(authUrl);
      const req = https.request({
        hostname: u.hostname,
        path: u.pathname + u.search,
        method: 'GET',
        headers: {
          'Cookie': cookieHeader,
          'User-Agent': DEFAULT_USER_AGENT
        }
      }, res => {
        const loc = res.headers.location;
        if (!loc) {
          return reject(new Error(`No redirect location received from Live.com (HTTP ${res.statusCode})`));
        }
        const hash = loc.split('#')[1] || '';
        const params = new URLSearchParams(hash);
        const token = params.get('access_token');
        if (token) {
          resolve(token);
        } else {
          reject(new Error(`No access_token found in redirect: ${loc}`));
        }
      });
      req.on('error', reject);
      req.end();
    });
  } catch (err) {
    // If Live.com cookie authorization fails, fallback to extracting OAuth2 refresh token
    const rawRefreshToken = extractRefreshToken(cookieContent);
    if (rawRefreshToken) {
      return await refreshTokenToJwt(rawRefreshToken, proxy);
    }
    throw err;
  }

  // Step 2: Authenticate with Xbox Live (XBL) using compact ticket (t=...)
  const rpsTicket = msAccessToken.startsWith('d=') || msAccessToken.startsWith('t=') ? msAccessToken : `t=${msAccessToken}`;
  const xblBody = JSON.stringify({
    Properties: { AuthMethod: 'RPS', SiteName: 'user.auth.xboxlive.com', RpsTicket: rpsTicket },
    RelyingParty: 'http://auth.xboxlive.com',
    TokenType: 'JWT'
  });

  const xblData = await requestJson(
    'https://user.auth.xboxlive.com/user/authenticate',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: xblBody
    },
    proxy
  );

  const xblToken = xblData?.Token;
  const userHash = xblData?.DisplayClaims?.xui?.[0]?.uhs;

  if (!xblToken || !userHash) {
    throw new Error('Xbox Live authentication failed');
  }

  // Step 3: Authorize with XSTS for Minecraft Services
  const xstsBody = JSON.stringify({
    Properties: {
      SandboxId: 'RETAIL',
      UserTokens: [xblToken]
    },
    RelyingParty: 'rp://api.minecraftservices.com/',
    TokenType: 'JWT'
  });

  const xstsData = await requestJson(
    'https://xsts.auth.xboxlive.com/xsts/authorize',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: xstsBody
    },
    proxy
  );

  const xstsToken = xstsData?.Token;
  if (!xstsToken) {
    throw new Error('XSTS authorization failed');
  }

  // Step 4: Login to Minecraft Services with Xbox Token
  const mcBody = JSON.stringify({
    identityToken: `XBL3.0 x=${userHash};${xstsToken}`
  });

  const mcData = await requestJson(
    'https://api.minecraftservices.com/authentication/login_with_xbox',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: mcBody
    },
    proxy
  );

  const jwtToken = mcData?.access_token;
  if (!jwtToken) {
    throw new Error('Minecraft services login failed to return access_token');
  }

  // Step 5: Fetch Player Profile
  const profile = await fetchMinecraftProfile(jwtToken, proxy);

  const sessionResult = {
    accessToken: jwtToken,
    username: profile.username || 'Player',
    uuid: profile.uuid || ''
  };

  // Cache token for 24h
  setCachedSession(cookieContent, sessionResult, mcData?.expires_in || 86400);

  return sessionResult;
}

/**
 * Converts Microsoft OAuth Refresh Token to Minecraft JWT Access Token
 */
async function refreshTokenToJwt(refreshToken, proxy = null) {
  if (!refreshToken) {
    throw new Error('Refresh token is required');
  }

  let cleanToken = refreshToken.trim().replace(/^11-/, '').replace(/\$$/, '').trim();

  // Check cache first!
  const cached = getCachedSession(cleanToken);
  if (cached) {
    return cached;
  }

  // Step 1: Exchange Refresh Token for Microsoft Access Token
  const tokenParams = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    refresh_token: cleanToken,
    grant_type: 'refresh_token',
    scope: 'service::user.auth.xboxlive.com::MBI_SSL'
  });

  const msData = await requestJson(
    'https://login.live.com/oauth20_token.srf',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: tokenParams.toString()
    },
    proxy
  );

  if (!msData || !msData.access_token) {
    throw new Error(`Microsoft OAuth exchange failed: ${JSON.stringify(msData)}`);
  }

  const msAccessToken = msData.access_token;
  const newRefreshToken = msData.refresh_token || cleanToken;

  // Step 2: Authenticate with Xbox Live (XBL)
  const rpsTicket = msAccessToken.startsWith('d=') || msAccessToken.startsWith('t=') ? msAccessToken : `t=${msAccessToken}`;
  const xblBody = JSON.stringify({
    Properties: {
      AuthMethod: 'RPS',
      SiteName: 'user.auth.xboxlive.com',
      RpsTicket: rpsTicket
    },
    RelyingParty: 'http://auth.xboxlive.com',
    TokenType: 'JWT'
  });

  const xblData = await requestJson(
    'https://user.auth.xboxlive.com/user/authenticate',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: xblBody
    },
    proxy
  );

  const xblToken = xblData?.Token;
  const userHash = xblData?.DisplayClaims?.xui?.[0]?.uhs;

  if (!xblToken || !userHash) {
    throw new Error('Xbox Live authentication failed');
  }

  // Step 3: Authorize with XSTS for Minecraft Services
  const xstsBody = JSON.stringify({
    Properties: {
      SandboxId: 'RETAIL',
      UserTokens: [xblToken]
    },
    RelyingParty: 'rp://api.minecraftservices.com/',
    TokenType: 'JWT'
  });

  const xstsData = await requestJson(
    'https://xsts.auth.xboxlive.com/xsts/authorize',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: xstsBody
    },
    proxy
  );

  const xstsToken = xstsData?.Token;
  if (!xstsToken) {
    throw new Error('XSTS authorization failed');
  }

  // Step 4: Login to Minecraft Services with Xbox Token to get Minecraft JWT
  const mcBody = JSON.stringify({
    identityToken: `XBL3.0 x=${userHash};${xstsToken}`
  });

  const mcData = await requestJson(
    'https://api.minecraftservices.com/authentication/login_with_xbox',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: mcBody
    },
    proxy
  );

  const jwtToken = mcData?.access_token;
  if (!jwtToken) {
    throw new Error('Minecraft services login failed to return access_token');
  }

  // Step 5: Fetch Player Profile (Username and UUID)
  const profile = await fetchMinecraftProfile(jwtToken, proxy);

  const sessionResult = {
    accessToken: jwtToken,
    newRefreshToken,
    username: profile.username || 'Player',
    uuid: profile.uuid || ''
  };

  // Cache token for 24h
  setCachedSession(cleanToken, sessionResult, mcData?.expires_in || 86400);

  return sessionResult;
}

/**
 * Extracts Microsoft refresh token from Netscape cookie format, JSON, or raw text.
 */
function extractRefreshToken(input) {
  if (!input || typeof input !== 'string') return null;
  const trimmed = input.trim();

  function sanitize(t) {
    if (!t) return null;
    return t.trim().replace(/^11-/, '').replace(/\$$/, '').trim();
  }

  // 1. If it's already a direct refresh token
  if (trimmed.startsWith('M.C') || trimmed.startsWith('M.R') || trimmed.startsWith('11-M.C') || trimmed.startsWith('11-M.R')) {
    return sanitize(trimmed.split(/\s+/)[0]);
  }

  // 2. Netscape cookie format / text lines
  const lines = trimmed.split(/\r?\n/);
  for (const line of lines) {
    const l = line.trim();
    if (l.startsWith('# RefreshToken:')) {
      return sanitize(l.replace('# RefreshToken:', ''));
    }
    if (l.includes('__Host-MSAAUTHP')) {
      const parts = l.split('\t');
      if (parts.length >= 7) {
        return sanitize(parts[6]);
      }
      const spaceParts = l.split(/\s+/);
      const hostIdx = spaceParts.findIndex(p => p === '__Host-MSAAUTHP');
      if (hostIdx !== -1 && spaceParts[hostIdx + 1]) {
        return spaceParts[hostIdx + 1];
      }
    }
  }

  // 3. JSON format
  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed)) {
      const cookie = parsed.find(c => c && (c.name === '__Host-MSAAUTHP' || c.name === 'RefreshToken'));
      if (cookie && cookie.value) return sanitize(cookie.value);
    } else if (parsed && typeof parsed === 'object') {
      if (parsed.refreshToken) return sanitize(parsed.refreshToken);
      if (parsed.refresh_token) return sanitize(parsed.refresh_token);
      if (parsed.__Host_MSAAUTHP) return sanitize(parsed.__Host_MSAAUTHP);
    }
  } catch (_) {}

  // 4. Regex search for M.C or M.R token in the text
  const match = trimmed.match(/(?:11-)?M\.[CR][A-Za-z0-9_\.\-!*]+(?:\$)?/);
  if (match) {
    return sanitize(match[0]);
  }

  return null;
}

/**
 * Fetches Minecraft profile (username and UUID) using JWT access token
 */
async function fetchMinecraftProfile(jwtToken, proxy = null) {
  try {
    const profile = await requestJson(
      'https://api.minecraftservices.com/minecraft/profile',
      {
        method: 'GET',
        headers: { Authorization: `Bearer ${jwtToken}` }
      },
      proxy
    );
    if (profile && profile.name) {
      return {
        username: profile.name,
        uuid: profile.id
      };
    }
    if (profile && (profile.error === 'NOT_FOUND' || profile.errorMessage?.includes('Not Found'))) {
      throw new Error('This Microsoft account does NOT own Minecraft Java Edition or has no in-game profile created (404 Not Found).');
    }
  } catch (err) {
    if (err && (err.message.includes('404') || err.message.includes('NOT_FOUND') || err.message.includes('own Minecraft'))) {
      throw new Error('This Microsoft account does NOT own Minecraft Java Edition or has no in-game profile created.');
    }
    if (err && err.message.includes('429')) {
      throw err;
    }
  }

  const payloadProfile = parseJwtPayload(jwtToken);
  if (!payloadProfile.username || payloadProfile.username === 'Player') {
    throw new Error('This account has no valid Minecraft profile name.');
  }
  return payloadProfile;
}

/**
 * Parses payload from JWT token
 */
function parseJwtPayload(jwtToken) {
  try {
    const parts = jwtToken.split('.');
    if (parts.length >= 2) {
      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
      const username = payload.pfd?.[0]?.name || payload.profiles?.mc || payload.extra?.username || null;
      const uuid = payload.sub || null;
      return {
        username: username || 'Player',
        uuid: uuid || ''
      };
    }
  } catch (_) {}
  return { username: 'Player', uuid: '' };
}

module.exports = {
  refreshTokenToJwt,
  cookieFileToJwt,
  cookiesToJwt,
  requestJson,
  extractRefreshToken,
  fetchMinecraftProfile,
  parseJwtPayload,
  getCachedSession,
  setCachedSession,
  clearCachedSession
};