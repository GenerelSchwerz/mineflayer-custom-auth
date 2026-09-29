'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { parseEnv } = require('node:util');

function loadConfiguration(args, inherited = process.env) {
  let envPath = path.join(__dirname, '.env');
  let input;
  let showToken = false;
  let checkConfig = false;
  let timeout = 60000;
  let clientId;
  let inputType;
  let headless = true;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--show-token') showToken = true;
    else if (arg === '--check-config') checkConfig = true;
    else if (arg === '--visible' || arg === '--no-headless') headless = false;
    else if (arg === '--debug' || arg === '--verbose') process.env.DEBUG = process.env.DEBUG || 'mineflayer-custom-auth*';
    else if (['--env', '--timeout', '--client-id', '--input-type', '--headless'].includes(arg)) {
      const value = args[++i];
      if (!value || value.startsWith('--')) throw new Error(`Missing value for ${arg}.`);
      if (arg === '--env') envPath = path.resolve(value);
      if (arg === '--timeout') timeout = Number(value);
      if (arg === '--client-id') clientId = value;
      if (arg === '--input-type') inputType = value;
      if (arg === '--headless') headless = value !== 'false';
    } else if (!arg.startsWith('--') && input === undefined) input = arg;
    else throw new Error('Usage: node refresh_single.js [file-or-token] [--env PATH] [--input-type auto|refresh-token|msauth-cookie] [--client-id ID] [--timeout MS] [--check-config] [--show-token] [--visible] [--debug]');
  }
  if (!Number.isInteger(timeout) || timeout <= 0 || timeout > 2147483647) throw new Error('Invalid timeout in milliseconds.');
  let saved = {};
  if (fs.existsSync(envPath)) {
    if (typeof parseEnv !== 'function') throw new Error('This CLI requires Node.js 20.12 or newer.');
    const content = fs.readFileSync(envPath, 'utf8');
    const keys = new Set();
    for (const line of content.split(/\r?\n/)) {
      const key = line.match(/^\s*(?:export\s+)?(REFRESH_TOKEN|MSAAUTH_COOKIE|COOKIE_FILE)\s*=/)?.[1];
      if (key && keys.has(key)) throw new Error(`Duplicate ${key} in ${envPath}; keep one entry.`);
      if (key) keys.add(key);
    }
    saved = parseEnv(content);
  } else if (args.includes('--env')) throw new Error(`Environment file not found: ${envPath}`);
  const env = { ...inherited, ...saved };
  inputType = inputType || env.AUTH_INPUT_TYPE;
  if (inputType && !['auto', 'refresh-token', 'msauth-cookie'].includes(inputType)) throw new Error('Input type must be auto, refresh-token, or msauth-cookie.');
  let source = 'command-line argument';
  let selectedKey;
  if (input === undefined) {
    const names = ['COOKIE_FILE', 'MSAAUTH_COOKIE', 'REFRESH_TOKEN'];
    // A saved credential setting, including an empty value, supersedes inherited credentials.
    const credentials = names.some(key => Object.hasOwn(saved, key)) ? saved : env;
    const configured = names.filter(key => credentials[key]?.trim());
    if (configured.length > 1) throw new Error('Set only one of COOKIE_FILE, MSAAUTH_COOKIE, or REFRESH_TOKEN.');
    if (!configured.length) throw new Error(`No input. Set REFRESH_TOKEN, MSAAUTH_COOKIE, or COOKIE_FILE in ${envPath}, or pass a file/token argument.`);
    selectedKey = configured[0];
    input = credentials[selectedKey].trim();
    source = Object.hasOwn(saved, selectedKey) ? `${envPath} (${selectedKey})` : `process environment (${selectedKey})`;
    if (selectedKey === 'COOKIE_FILE' && Object.hasOwn(saved, selectedKey)) input = path.resolve(path.dirname(envPath), input);
  }
  inputType = inputType || (selectedKey === 'REFRESH_TOKEN' ? 'refresh-token' : 'auto');
  input = input.trim().replace(/^(["'])(.*)\1$/, '$2');
  if (!input) throw new Error('Input is empty.');
  const isFile = fs.existsSync(input);
  if (isFile && !fs.statSync(input).isFile()) throw new Error('Input must be a file, not a directory.');
  if (!isFile && (selectedKey === 'COOKIE_FILE' || /^(?:[a-z]:[\\/]|\.{1,2}[\\/]|[\\/])/i.test(input) || /\.(txt|json)$/i.test(input))) throw new Error('Input file does not exist.');
  const material = isFile ? fs.readFileSync(input, 'utf8').trim() : input;
  if (!material) throw new Error('Input file is empty.');
  const fingerprint = crypto.createHash('sha256').update(material).digest('hex').slice(0, 12);
  const options = {
    fetchProfile: true, forceRefresh: true, timeout,
    headless,
    onStatus: (msg) => console.log(`[*] ${msg}`),
    profilesFolder: path.join(__dirname, 'cache'),
    ...(clientId || env.MICROSOFT_CLIENT_ID ? { authTitle: clientId || env.MICROSOFT_CLIENT_ID, microsoftClientId: clientId || env.MICROSOFT_CLIENT_ID } : {}),
    ...(env.MICROSOFT_REDIRECT_URI ? { microsoftRedirectUri: env.MICROSOFT_REDIRECT_URI } : {}),
    ...(env.MICROSOFT_SCOPE ? { microsoftScope: env.MICROSOFT_SCOPE } : {}),
    ...(env.PROXY ? { proxy: env.PROXY } : {}),
  };
  return { input, material, selectedKey, source, fingerprint, isFile, options, showToken, checkConfig, envPath, inputType };
}

async function main(args = process.argv.slice(2)) {
  const config = loadConfiguration(args);
  console.log(`Input source: ${config.source}`);
  if (config.isFile) console.log(`Input file: ${path.resolve(config.input)}`);
  console.log(`Input fingerprint (SHA-256): ${config.fingerprint}`);
  console.log(`Input type: ${config.inputType}`);
  if (config.checkConfig) return;
  const { getAccessToken, getAccessTokenFromRefreshToken, getAccessTokenFromMsauthCookie } = require('./dist');
  const deadline = setTimeout(() => {
    console.error(`Authentication timed out after ${config.options.timeout} ms.`);
    if (config.inputType !== 'refresh-token') {
      console.error('\nNote: Cookie authentication timed out. This typically means:');
      console.error('  1. The cookies in your file have expired or lack an active Microsoft session.');
      console.error('  2. Microsoft triggered an interactive prompt (e.g. 2FA code, CAPTCHA, or password re-entry).');
      console.error('Tip: Re-run with --visible to see the browser window and inspect what Microsoft is displaying.');
    }
    process.exit(1);
  }, config.options.timeout);
  try {
    const input = config.selectedKey === 'MSAAUTH_COOKIE' ? { msauthCookie: config.input } : config.input;
    let result;
    if (config.inputType === 'auto') result = await getAccessToken(input, config.options);
    else {
      let token = config.material.trim().replace(/^(["'])(.*)\1$/, '$2');
      if (token.startsWith('{') || token.startsWith('[')) {
        let parsed;
        try { parsed = JSON.parse(token); } catch { throw new Error('Invalid token JSON.'); }
        const record = Array.isArray(parsed) ? (parsed.length === 1 ? parsed[0] : null) : parsed;
        token = record?.refresh_token ?? record?.refreshToken ?? record?.token;
      }
      if (typeof token !== 'string' || !token.trim() || /[\r\n\t]/.test(token)) throw new Error('Explicit token mode requires a token or single-token file. Use auto for cookie exports.');
      result = config.inputType === 'refresh-token'
        ? await getAccessTokenFromRefreshToken(token, config.options)
        : await getAccessTokenFromMsauthCookie(token, config.options);
    }
    console.log(JSON.stringify({
      success: true, username: result.username, uuid: result.uuid,
      expires_in: result.expiresIn, input_fingerprint: config.fingerprint,
      ...(config.showToken ? { minecraft_access_token: result.accessToken } : {}),
    }, null, 2));
    if (!config.showToken) console.log('Use --show-token to print the Minecraft access token.');
  } catch (error) {
    throw new Error(String(error.message || error).split(config.material).join('[redacted]'));
  } finally {
    clearTimeout(deadline);
  }
}

if (require.main === module) main().catch(error => {
  console.error(`Authentication failed: ${error.message}`);
  process.exitCode = 1;
});

module.exports = { main, loadConfiguration };
