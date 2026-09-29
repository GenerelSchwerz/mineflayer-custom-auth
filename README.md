# mineflayer-custom-auth

Extra authentication methods for **[mineflayer](https://github.com/PrismarineJS/mineflayer)** and standalone token extraction utilities for Minecraft Java Edition.

[![GitHub](https://img.shields.io/badge/GitHub-Osamu--GWAD%2Fmineflayer--custom--auth-blue)](https://github.com/Osamu-GWAD/mineflayer-custom-auth)
[![Node](https://img.shields.io/badge/Node.js-%3E%3D22.12.0-green)](https://nodejs.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Features

- 🍪 **Cookie-Based Login**: Login using Microsoft account cookies without user interaction.
  - Supports **Netscape `.txt`**, **JSON arrays** (Cookie-Editor, EditThisCookie), and raw HTTP header strings.
  - Load directly from file paths (`cookieFile: "./account.txt"`).
  - Handles Chromium `__Host-` strict cookie requirements (e.g., `__Host-MSAAUTH`).
  - Automated stealth Puppeteer browser with anti-detection headers, User-Agent rotation, and Microsoft Terms of Use auto-bypass.
  - Fast Sisu OAuth token interception directly from Microsoft Services.
- 🔄 **OAuth Refresh Token Login**: Authenticate directly using a Microsoft OAuth refresh token.
- 🔑 **Direct Access Token Login**: Pass an existing Minecraft Java Bearer access token.
- ⚡ **Unified `getAccessToken` API**: Automatically detects cookie files vs. refresh tokens and exchanges them for valid Minecraft Java access tokens and player profiles (`username`, `uuid`).
- 🛠️ **Standalone CLI (`refresh_single.js`)**: Quick diagnostics, profile verification, and token conversion without starting a Mineflayer bot.

---

## Installation

Requires **Node.js 22.12 or newer** (tested with Node 22 & 24).

### Option 1: Install from GitHub
```bash
npm install github:Osamu-GWAD/mineflayer-custom-auth
```

### Option 2: Clone and Build Locally
```powershell
git clone https://github.com/Osamu-GWAD/mineflayer-custom-auth.git
cd mineflayer-custom-auth
npm install
npm run build
```

To install your local clone into another project:
```powershell
npm install /path/to/mineflayer-custom-auth
```

---

## Quick Start: Testing & Running

### 1. Build TypeScript
Compile the TypeScript sources in `src/` to `dist/`:
```powershell
npm run build
```

### 2. Run Test Suites
Run the automated test suite (29 regression tests covering OAuth tokens, cookie handling, cache invalidation, and library integrations):
```powershell
npm test
```

To run the fast routing test for the unified authentication API:
```powershell
node test/unifiedAuth.test.js
```

---

## Standalone CLI (`refresh_single.js`)

You can convert credentials or verify accounts without starting a Mineflayer bot.

### 1. Configure Credentials
Copy `.env.example` to `.env`:
```powershell
# Windows PowerShell / CMD:
copy .env.example .env

# Linux / macOS:
cp .env.example .env
```

Configure **exactly one** credential source in `.env`:
```env
# Option A: Microsoft OAuth Refresh Token
REFRESH_TOKEN=M.R3_BL2_...

# Option B: Path to exported cookies file (.txt or .json)
COOKIE_FILE=./cookies.txt

# Option C: Direct MSAAUTHP session cookie
# MSAAUTH_COOKIE=...
```

### 2. Verify Configuration (No Network Calls)
Validate your `.env` and credential input locally without sending any network requests:
```powershell
node refresh_single.js --check-config
```

### 3. Run Token Exchange & Account Verification
Run using the credentials configured in `.env`:
```powershell
node refresh_single.js
```

Output:
```json
Input source: .env (REFRESH_TOKEN)
Input fingerprint (SHA-256): 64857b9dd310
Input type: refresh-token
{
  "success": true,
  "username": "PlayerName",
  "uuid": "293d14200afe429582968960107ea31c",
  "expires_in": 86400,
  "input_fingerprint": "64857b9dd310"
}
Use --show-token to print the Minecraft access token.
```

### 4. Passing Arguments Directly
You can also pass tokens or file paths directly via command-line arguments:
```powershell
node refresh_single.js .\cookies.txt
node refresh_single.js "M.R3_BL2_..."
```

---

## Token Output & Security FAQ

### Where does `node refresh_single.js` save the token?
**It does NOT save it anywhere on disk.**
- **In-Memory Only:** When you run `node refresh_single.js`, the authentication exchange happens entirely in memory with Microsoft, Xbox Live, and Minecraft APIs.
- **Redacted by Default:** To avoid accidentally exposing sensitive bearer credentials in terminal scrollback, CI/CD logs, or shell history, `minecraft_access_token` is hidden from the JSON output unless you explicitly pass `--show-token`.
- **Discarded on Exit:** Once the script finishes printing the account summary, the token in memory is discarded.

### How do I view or save the access token?
- **Display in terminal:**
  ```powershell
  node refresh_single.js --show-token
  ```
- **Save to a JSON file:**
  ```powershell
  node refresh_single.js --show-token > account.json
  ```
- **Custom Environment File:**
  ```powershell
  node refresh_single.js --env ./custom.env --show-token
  ```

---

## Mineflayer Bot Integration

### 1. Cookie Authentication
Pass either a file path (`cookieFile`) or parsed cookies (`cookies`):

```js
const { createBot } = require('mineflayer-custom-auth');

const bot = createBot({
  host: 'localhost',
  port: 25565,
  username: 'my-account',
  auth: 'cookies',
  cookieOptions: {
    cookieFile: './cookies.txt',  // Netscape .txt or JSON cookie array
    authMethod: 'auto',           // "auto" (browserless first, fallback to browser) | "browser" | "browserless"
    headless: true,
  },
});

bot.on('spawn', () => console.log(`Connected as ${bot.username}`));
bot.on('error', err => console.error('Bot error:', err.message));
```

### 2. OAuth Refresh Token Authentication
Pass your Microsoft OAuth refresh token:

```js
const { createBot } = require('mineflayer-custom-auth');

const bot = createBot({
  host: 'localhost',
  port: 25565,
  auth: 'refreshToken',
  refreshToken: process.env.REFRESH_TOKEN,
});

bot.on('spawn', () => console.log(`Connected as ${bot.username}`));
bot.on('error', err => console.error('Bot error:', err.message));
```

### 3. Direct Minecraft Access Token
If you already have a valid Minecraft Java Bearer token:

```js
const { createBot } = require('mineflayer-custom-auth');

const bot = createBot({
  host: 'localhost',
  port: 25565,
  auth: 'accessToken',
  javaAccessToken: 'your-bearer-access-token',
});

bot.on('spawn', () => console.log(`Connected as ${bot.username}`));
```

---

## Programmatic Token Retrieval

### Unified Auto-Detection (`getAccessToken`)
Accepts either a cookie file path or a refresh token string and automatically selects the proper exchange pipeline:

```ts
import { getAccessToken } from 'mineflayer-custom-auth';

// 1. From a cookie file (.txt or .json)
const cookieAuth = await getAccessToken('./cookies.txt', {
  headless: true,
  fetchProfile: true,
});
console.log('Username:', cookieAuth.username);
console.log('Token:', cookieAuth.accessToken);

// 2. From a Microsoft OAuth refresh token
const tokenAuth = await getAccessToken(process.env.REFRESH_TOKEN);
console.log('Username:', tokenAuth.username);
console.log('Token:', tokenAuth.accessToken);
```

### Direct Stealth Browser Login (`getAccessTokenFromBrowser`)
```ts
import { getAccessTokenFromBrowser } from 'mineflayer-custom-auth';

const result = await getAccessTokenFromBrowser('./cookies.txt', {
  headless: false, // show visible browser window
  timeout: 60000,
  fetchProfile: true,
});

console.log(`Authenticated as ${result.username} (${result.uuid})`);
```

### Direct Refresh Token Exchange (`getAccessTokenFromRefreshToken`)
```ts
import { getAccessTokenFromRefreshToken } from 'mineflayer-custom-auth';

const result = await getAccessTokenFromRefreshToken('M.R3_BL2_...', {
  fetchProfile: true,
});

console.log(`Authenticated as ${result.username} (${result.uuid})`);
```

---

## Runnable Bot Examples

Ready-to-use bot examples are located in [`examples/`](./examples):

- **OAuth Refresh Token:**
  ```powershell
  node --env-file=.env examples/refresh-token.js localhost 25565
  ```
- **Cookie File:**
  ```powershell
  node examples/cookies.js ./cookies.txt localhost 25565
  ```
- **Direct Access Token:**
  ```powershell
  node --env-file=.env examples/access-token.js localhost 25565
  ```

---

## API Reference

### Standalone Token Methods
- `getAccessToken(input, options?)` - Unified method accepting cookie file path, cookie array, cookie string, or refresh token string.
- `getMinecraftToken(input, options?)` - Alias for `getAccessToken`.
- `getAccessTokenFromBrowser(input, options?)` - Launches a stealth Puppeteer browser with cookies to obtain Minecraft token.
- `getAccessTokenFromRefreshToken(refreshToken, options?)` - Exchanges OAuth refresh token for Minecraft token.

### Cookie Utilities (`cookie.*`)
- `cookie.loadCookies(input)` - Loads cookies from file path, array of file paths, cookie string, or array of cookie objects.
- `cookie.parseCookies(str)` - Parses Netscape format cookie string (handles `#HttpOnly_`).
- `cookie.parseJsonCookies(json)` - Parses JSON array of cookie objects.
- `cookie.parseHeaderCookies(header, domain)` - Parses standard `Cookie:` or `Set-Cookie:` header string.

---

## Documentation

- [Cookie Login & Formats Guide](./docs/COOKIES.md)
- [Bot Examples Documentation](./examples/README.md)

---

## License & Credits

- License: MIT
- Original upstream project: [generel](https://ko-fi.com/generel)
- Maintained by: [Osamu-GWAD](https://github.com/Osamu-GWAD)
