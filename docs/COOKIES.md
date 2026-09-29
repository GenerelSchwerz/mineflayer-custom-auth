# Cookie Login Documentation

`mineflayer-custom-auth` provides advanced cookie authentication support for Microsoft accounts, enabling automated login into Minecraft Java Edition via browser-based Puppeteer automation or lightweight browserless requests.

---

## Supported Cookie Formats

The cookie loader automatically detects and handles multiple formats:

### 1. Netscape HTTP Cookie File (`.txt`)
Commonly exported by browser extensions (e.g., *Cookie-Editor*, *Get cookies.txt LOCALLY*) or cookie grabbers.

```tsv
# Netscape HTTP Cookie File
# http://curl.haxx.se/rfc/cookie_spec.html
# This is a generated file!  Do not edit.

.login.live.com	TRUE	/	TRUE	1893456000	MSPAuth	<value>
.live.com	TRUE	/	TRUE	1893456000	PPLState	1
#HttpOnly_login.live.com	FALSE	/	TRUE	1893456000	__Host-MSAAUTH	<value>
```

- Lines starting with `#HttpOnly_` are recognized as HttpOnly cookies.
- Empty lines and regular comments (`# `) are ignored.
- Tabs or multiple spaces can separate fields.

### 2. JSON Cookie Array (`.json` or string)
Exported as JSON from browser developer tools or extensions like *EditThisCookie*:

```json
[
  {
    "name": "__Host-MSAAUTH",
    "value": "AQABAAAA...",
    "domain": "login.live.com",
    "path": "/",
    "secure": true,
    "httpOnly": true
  },
  {
    "name": "PPLState",
    "value": "1",
    "domain": ".live.com",
    "path": "/",
    "secure": true
  }
]
```

### 3. HTTP Header String
Standard semicolon-separated `Cookie:` header:

```
__Host-MSAAUTH=AQABAAAA...; PPLState=1; MSPAuth=...
```

---

## Loading Cookies

You can pass cookie files directly to the helper functions or in `cookieOptions`:

```ts
import { cookie } from "mineflayer-custom-auth";

// Load from a single file
const cookies = cookie.loadCookies("./cookies.txt");

// Load and merge multiple cookie files
const mergedCookies = cookie.loadCookies([
  "./cookies_live.txt",
  "./cookies_xbox.txt"
]);

// Or pass raw text
const parsed = cookie.parseCookies(rawText);
```

### Chromium `__Host-` Cookie Handling
Chromium strictly validates cookies with the `__Host-` prefix (such as Microsoft's `__Host-MSAAUTH`). Under RFC 6265bis, `__Host-` cookies:
- Must have `secure: true`
- Must have `path: "/"`
- Must **not** specify a domain attribute (host-only)

`mineflayer-custom-auth` automatically normalizes and strips invalid domain attributes on `__Host-` cookies before injecting them into Chromium, preventing `Protocol error (Network.setCookies): Invalid cookie fields`.

---

## Browser Automation & Sisu Interception

When using `authMethod: "browser"` or standalone browser functions:

1. **Anti-Detection Stealth**:
   - Randomizes desktop User-Agents.
   - Clears `navigator.webdriver`.
   - Injects realistic viewport and navigator properties (`hardwareConcurrency`, `deviceMemory`, plugins, languages).
   - Injects anti-bot bypass scripts into new documents.

2. **Microsoft Terms of Use ("We're updating our terms")**:
   - If Microsoft displays the `account.live.com/tou/accrue` interstitial page, the authenticator automatically detects the `Next` button (`#iNext`) and proceeds seamlessly.

3. **Sub-second Sisu Interception**:
   - The browser navigates to the Microsoft Sisu OAuth authorization URL (`sisu.xboxlive.com`).
   - The authenticator catches the OAuth redirect to `minecraft.net/#accessToken=...`.
   - The token payload is parsed immediately and exchanged directly with `api.minecraftservices.com/authentication/login_with_xbox` to obtain the final Minecraft Java access token without waiting for the full client-side page load.

---

## Auth Methods

`cookieOptions.authMethod` controls how cookies are exchanged:

- `"browser"`: Launches Puppeteer with stealth configuration and cookie injection.
- `"browserless"`: Lightweight HTTP/HTTPS request flow without opening a browser.
- `"auto"`: *(Default)* Tries the browserless flow first for speed; if it encounters anti-bot challenges or redirects, falls back to the browser flow.

```ts
cookieOptions: {
  cookieFile: "./cookies.txt",
  authMethod: "browser",
  headless: true, // false to see the browser window
  timeout: 60000,
  proxy: "https://127.0.0.1:8080",
  allowUnsafeProxyTls: true,
}
```

---

## Proxy Support

- **Browserless**: Supports `http://`, `https://`, `socks://`, `socks4://`, and `socks5://`.
- **Browser (Puppeteer)**: Supports `http://` and `https://` proxy URLs.
- `allowUnsafeProxyTls: true`: Bypasses TLS certificate verification (useful for Charles, Fiddler, Mitmproxy, or self-signed proxies).
