import puppeteer, { Browser, Page } from "puppeteer";
import https from "https";
import { cookie } from "./cookie";
import { assertBrowserProxy, buildProxyUrl } from "./proxy";
import type { ProxyConfig } from "../types";
import { getJwtExpiry } from "../utils";

const debug = require("debug")("mineflayer-custom-auth:cookie-browser");

export interface BrowserAuthOptions {
  headless?: boolean;
  executablePath?: string;
  proxy?: ProxyConfig | string;
  allowUnsafeProxyTls?: boolean;
  timeout?: number;
  fetchProfile?: boolean;
  userAgent?: string;
  onStatus?: (status: string) => void;
}

export interface BrowserAuthResult {
  accessToken: string;
  username?: string;
  uuid?: string;
  expiresIn?: number;
  obtainedOn: number;
}

const DEFAULT_TIMEOUT = 45000;
const MINECRAFT_PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile";

/**
 * Extract token from a raw cookie string (e.g. document.cookie)
 */
function extractAccessTokenFromCookieString(cookieString: string): string | undefined {
  if (!cookieString) return undefined;
  const match = cookieString.match(/(?:^|;\s*)bearer_token=([^;]+)/i);
  if (match?.[1] && match[1].startsWith("ey")) {
    return match[1].trim();
  }
  return undefined;
}

function decodeBase64Json<T>(value: string): T {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return JSON.parse(Buffer.from(padded, "base64").toString("utf8")) as T;
}

function buildMinecraftIdentityTokenFromSisu(sisuAccessToken: string): string {
  const items = decodeBase64Json<any[]>(sisuAccessToken);
  const minecraftItem = items.find((item) => item.Item1?.toLowerCase() === "rp://api.minecraftservices.com/");
  const token = minecraftItem?.Item2?.Token;
  const uhs = minecraftItem?.Item2?.DisplayClaims?.xui?.[0]?.uhs;
  if (!token || !uhs) throw new Error("Sisu access token did not include a Minecraft Services XBL token.");
  return `XBL3.0 x=${uhs};${token}`;
}

async function exchangeSisuTokenForMinecraftToken(
  sisuToken: string,
  proxy?: ProxyConfig | string,
  allowUnsafeProxyTls = false
): Promise<string> {
  const identityToken = buildMinecraftIdentityTokenFromSisu(sisuToken);
  const parsedProxy = buildProxyUrl(proxy);
  const { HttpsProxyAgent } = require("https-proxy-agent");
  const agent = parsedProxy ? new HttpsProxyAgent(parsedProxy.url) : undefined;

  return new Promise((resolve, reject) => {
    const postData = JSON.stringify({ identityToken, platform: "WEB", ensureLegacyEnabled: true });
    const req = https.request(
      "https://api.minecraftservices.com/authentication/login_with_xbox",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          "Content-Length": Buffer.byteLength(postData),
        },
        agent,
        rejectUnauthorized: allowUnsafeProxyTls ? false : undefined,
        timeout: 15000,
      },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => {
          if (res.statusCode === 200) {
            try {
              const parsed = JSON.parse(body);
              if (parsed.access_token) return resolve(parsed.access_token);
            } catch {}
          }
          reject(new Error(`Minecraft login returned HTTP ${res.statusCode}: ${body.slice(0, 200)}`));
        });
      }
    );
    req.on("error", reject);
    req.write(postData);
    req.end();
  });
}

/**
 * Fetch the Minecraft profile for a given access token
 */
async function fetchMinecraftProfile(
  accessToken: string,
  proxy?: ProxyConfig | string,
  allowUnsafeProxyTls = false
): Promise<{ id: string; name: string } | undefined> {
  const { HttpsProxyAgent } = require("https-proxy-agent");
  const parsedProxy = buildProxyUrl(proxy);
  const agent = parsedProxy ? new HttpsProxyAgent(parsedProxy.url) : undefined;

  return new Promise((resolve) => {
    const req = https.request(
      MINECRAFT_PROFILE_URL,
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/json",
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        },
        agent,
        rejectUnauthorized: allowUnsafeProxyTls ? false : undefined,
        timeout: 10000,
      },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => {
          if (res.statusCode === 200) {
            try {
              const data = JSON.parse(body);
              if (data.id && data.name) {
                return resolve({ id: data.id, name: data.name });
              }
            } catch {
              // ignore json parse error
            }
          }
          resolve(undefined);
        });
      }
    );

    req.on("error", () => resolve(undefined));
    req.on("timeout", () => {
      req.destroy();
      resolve(undefined);
    });
    req.end();
  });
}

/**
 * Launch a browser, load the provided cookies or cookie file(s),
 * authenticate through Microsoft and Minecraft Services, and return the token.
 *
 * @param cookieInput - Cookie file path, array of file paths, cookie string, or Cookie array
 * @param options - Browser and network configuration options
 * @returns The authenticated Minecraft token and profile information
 */
export async function authenticateWithBrowserCookies(
  cookieInput: string | string[] | cookie.Cookie[] | Buffer,
  options: BrowserAuthOptions = {}
): Promise<BrowserAuthResult> {
  const cookies = cookie.loadCookies(cookieInput);
  if (!cookies || cookies.length === 0) {
    throw new Error("No valid cookies found in the provided cookie input or files.");
  }

  const timeoutMs = options.timeout ?? DEFAULT_TIMEOUT;
  const proxy = buildProxyUrl(options.proxy);
  if (proxy) assertBrowserProxy(proxy);

  const args: string[] = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-blink-features=AutomationControlled",
    "--no-first-run",
    "--no-default-browser-check",
    "--window-size=1280,800",
  ];

  let proxyUrl: URL | null = null;
  if (proxy != null) {
    proxyUrl = new URL(proxy.url);
    args.push(`--proxy-server=${proxyUrl.protocol}//${proxyUrl.host}`);
  }

  if (options.allowUnsafeProxyTls) {
    args.push("--ignore-certificate-errors");
  }

  debug("Launching browser for cookie authentication...");
  const browser: Browser = await puppeteer.launch({
    args,
    executablePath: options.executablePath || undefined,
    headless: options.headless ?? true,
  });

  try {
    const page: Page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });

    if (proxyUrl != null && proxyUrl.username && proxyUrl.password) {
      await page.authenticate({
        username: decodeURIComponent(proxyUrl.username),
        password: decodeURIComponent(proxyUrl.password),
      });
    }

    const userAgent =
      options.userAgent ||
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36";
    await page.setUserAgent(userAgent);

    // Evasion: disable navigator.webdriver flag
    await page.evaluateOnNewDocument(() => {
      Object.defineProperty(navigator, "webdriver", { get: () => undefined });
    });

    // Multi-channel token interceptor state
    let capturedToken: string | undefined;
    let tokenResolve: ((token: string) => void) | undefined;
    const tokenPromise = new Promise<string>((resolve) => {
      tokenResolve = resolve;
    });

    const setToken = (t: string) => {
      if (!capturedToken && t && t.startsWith("ey")) {
        capturedToken = t.trim();
        debug("Intercepted valid Minecraft access token!");
        tokenResolve?.(capturedToken);
      }
    };

    // Channel 1: Listen to network responses for tokens
    page.on("response", async (response) => {
      try {
        const url = response.url();

        // 1a. URL hash / query parameters (OAuth callback)
        if (url.includes("accessToken=") || url.includes("access_token=")) {
          const match = url.match(/[?#&]access_?token=([^&]+)/i);
          if (match?.[1]) {
            const raw = decodeURIComponent(match[1]);
            if (raw.startsWith("ey")) {
              setToken(raw);
            } else if (raw.startsWith("W3si") || raw.includes("Item1")) {
              debug("Captured Sisu token in OAuth URL, exchanging for Minecraft access token...");
              try {
                const javaToken = await exchangeSisuTokenForMinecraftToken(raw, options.proxy, options.allowUnsafeProxyTls);
                if (javaToken) setToken(javaToken);
              } catch (err) {
                debug("Sisu exchange error:", err);
              }
            }
          }
        }

        // 1b. Set-Cookie response header containing bearer_token
        const headers = response.headers();
        const setCookieHeader = headers["set-cookie"];
        if (setCookieHeader) {
          const match = setCookieHeader.match(/bearer_token=([^;]+)/i);
          if (match?.[1] && match[1].startsWith("ey")) {
            setToken(match[1]);
          }
        }

        // 1c. API login endpoint JSON responses
        if (
          url.includes("minecraftservices.com/authentication/login_with_xbox") ||
          url.includes("minecraftservices.com/launcher/login") ||
          url.includes("minecraft.net/api/v1/auth")
        ) {
          try {
            const text = await response.text();
            const data = JSON.parse(text);
            if (data.access_token && typeof data.access_token === "string" && data.access_token.startsWith("ey")) {
              setToken(data.access_token);
            }
          } catch {
            // ignore JSON error
          }
        }
      } catch {
        // ignore response listener errors
      }
    });

    // Channel 2: Listen to network requests for Authorization header
    page.on("request", (req) => {
      try {
        const auth = req.headers()["authorization"];
        if (auth && auth.toLowerCase().startsWith("bearer ey")) {
          const token = auth.slice(7).trim();
          if (token.startsWith("ey")) setToken(token);
        }
      } catch {
        // ignore
      }
    });

    // Helper: Handle Microsoft prompts (Stay signed in?, Terms of Use update, etc.)
    const handleIntermediatePrompts = async () => {
      try {
        const curUrl = page.url();
        if (curUrl.includes("/tou/") || curUrl.includes("account.live.com/tou/accrue")) {
          debug("Detected Microsoft Terms of Use update page, clicking Next...");
          const nextBtn = await page.$(
            "#iNext, input[type='submit'][value*='Next'], input[value*='Next'], button:has-text('Next')"
          );
          if (nextBtn) {
            await nextBtn.click().catch(() => {});
          }
        }

        const promptBtn = await page.$(
          "#idSIButton9, #declineButton, #acceptButton, input[type='submit'][value*='Yes'], input[type='submit'][value*='Next']"
        );
        if (promptBtn) {
          debug("Detected Microsoft prompt button, clicking...");
          await promptBtn.click().catch(() => {});
        }
      } catch {
        // ignore
      }
    };

    // Load cookies into browser context
    debug(`Setting ${cookies.length} cookies into browser context...`);
    const formattedCookies = cookies.map((c) => {
      const isHost = c.name?.startsWith("__Host-");
      let cleanDomain = (c.domain || "login.live.com").trim();
      while (cleanDomain.startsWith(".")) {
        cleanDomain = cleanDomain.substring(1);
      }
      const isMinecraft = cleanDomain.includes("minecraft.net");

      return {
        name: c.name,
        value: c.value,
        domain: isHost ? undefined : `.${cleanDomain}`,
        path: isHost ? "/" : (c.path || "/"),
        expires: c.expires && c.expires > 0 ? c.expires : undefined,
        httpOnly: Boolean(c.httpOnly),
        secure: isHost ? true : Boolean(c.secure),
        sameSite: (c.sameSite as "Strict" | "Lax" | "None") || "Lax",
        url: isMinecraft ? "https://www.minecraft.net" : `https://${cleanDomain}`,
      };
    });

    await page.setCookie(...formattedCookies);

    // Step 1: Navigate to login.live.com to activate session
    debug("Navigating to Microsoft Live to activate cookie session...");
    options.onStatus?.("Navigating to Microsoft Live to activate cookie session...");
    try {
      await page.goto("https://login.live.com", {
        waitUntil: "domcontentloaded",
        timeout: Math.min(timeoutMs, 20000),
      });
      await page.waitForNavigation({ waitUntil: "networkidle2", timeout: 5000 }).catch(() => {});
    } catch {
      // ignore redirect navigation error
    }

    await handleIntermediatePrompts();

    // Step 2: Navigate to Minecraft login
    debug("Navigating to Minecraft login page...");
    options.onStatus?.("Navigating to Minecraft login page...");
    await page.goto("https://www.minecraft.net/en-us/login", {
      waitUntil: "domcontentloaded",
      timeout: Math.min(timeoutMs, 20000),
    });

    // Check if token was already intercepted or if session redirected to profile
    if (!capturedToken) {
      // Look for Microsoft sign-in button
      const loginSelectors = [
        '[data-testid="MSALoginButtonLink"]',
        'a[href*="sisu.xboxlive.com"]',
        'a[href*="login.live.com"]',
        'button[data-testid="MSALoginButtonLink"]',
        'a[aria-label*="Microsoft"]',
        'button[aria-label*="Microsoft"]',
      ];

      for (const sel of loginSelectors) {
        const btn = await page.$(sel);
        if (btn) {
          debug(`Found Microsoft login button (${sel}), clicking...`);
          options.onStatus?.("Found Microsoft login button, clicking sign in...");
          await btn.click().catch(() => {});
          break;
        }
      }
    }

    // Step 3: Wait for token interception, handle prompts, and check cookies
    const startTime = Date.now();
    let waitingNotified = false;
    while (!capturedToken && Date.now() - startTime < timeoutMs) {
      if (!waitingNotified && Date.now() - startTime > 4000) {
        waitingNotified = true;
        options.onStatus?.(
          options.headless !== false
            ? "Waiting for token callback from Microsoft... Note: If it stays here, Microsoft is likely prompting for a CAPTCHA, 2FA code, or password re-entry. Re-run with --visible to inspect."
            : "Waiting for token callback from Microsoft... Please complete any CAPTCHA or login prompts in the browser window if displayed."
        );
      }
      await handleIntermediatePrompts();

      // Check cookies for bearer_token
      const pageCookies = await page.cookies().catch(() => []);
      for (const c of pageCookies) {
        if (c.name.toLowerCase() === "bearer_token" && c.value.startsWith("ey")) {
          setToken(c.value);
          break;
        }
      }

      if (capturedToken) break;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }

    // Step 4: Check document.cookie and localStorage as fallback
    if (!capturedToken) {
      debug("Evaluating document.cookie and storage...");
      const cookieStr = await page.evaluate(() => document.cookie).catch(() => "");
      const fromCookie = extractAccessTokenFromCookieString(cookieStr);
      if (fromCookie) setToken(fromCookie);

      if (!capturedToken) {
        const storageToken = await page
          .evaluate(() => {
            for (let i = 0; i < localStorage.length; i++) {
              const k = localStorage.key(i) || "";
              const val = localStorage.getItem(k);
              if (val && val.startsWith("ey")) return val;
              if (val && val.includes('"access_token":"ey')) {
                try {
                  const obj = JSON.parse(val);
                  if (obj.access_token) return obj.access_token;
                } catch {
                  // ignore
                }
              }
            }
            return null;
          })
          .catch(() => null);

        if (storageToken && typeof storageToken === "string" && storageToken.startsWith("ey")) {
          setToken(storageToken);
        }
      }
    }

    // Step 5: If still not captured, attempt navigating to profile page
    if (!capturedToken) {
      debug("Navigating to Minecraft profile page to trigger session token...");
      await page
        .goto("https://www.minecraft.net/en-us/msaprofile/mygames", {
          waitUntil: "domcontentloaded",
          timeout: 10000,
        })
        .catch(() => {});

      const profileCookies = await page.cookies().catch(() => []);
      for (const c of profileCookies) {
        if (c.name.toLowerCase() === "bearer_token" && c.value.startsWith("ey")) {
          setToken(c.value);
          break;
        }
      }

      if (!capturedToken) {
        const profileCookieStr = await page.evaluate(() => document.cookie).catch(() => "");
        const fromProfileCookie = extractAccessTokenFromCookieString(profileCookieStr);
        if (fromProfileCookie) setToken(fromProfileCookie);
      }
    }

    // If still no token, inspect page for error messages to provide clear feedback
    if (!capturedToken) {
      const pageText = await page.evaluate(() => document.body?.innerText || "").catch(() => "");
      if (pageText.includes("Your account has been locked") || pageText.includes("account is locked")) {
        throw new Error("Microsoft account is locked or suspended.");
      }
      if (pageText.includes("Help us protect your account") || pageText.includes("Verify your identity")) {
        throw new Error("Microsoft account requires 2FA or identity verification.");
      }
      if (pageText.includes("Sign-in blocked") || pageText.includes("blocked from signing in")) {
        throw new Error("Microsoft sign-in is blocked for this account.");
      }

      throw new Error(
        "Failed to extract Minecraft access token from browser. Ensure the cookie files contain valid Microsoft/Minecraft session cookies."
      );
    }

    // Step 6: Verify token expiry and fetch profile
    const obtainedOn = Date.now();
    const expiryTimestamp = getJwtExpiry(capturedToken);
    const expiresIn = expiryTimestamp ? Math.max(0, Math.floor((expiryTimestamp - obtainedOn) / 1000)) : 86400;

    let profile: { id: string; name: string } | undefined;
    if (options.fetchProfile !== false) {
      debug("Fetching Minecraft profile using extracted access token...");
      profile = await fetchMinecraftProfile(capturedToken, options.proxy, options.allowUnsafeProxyTls);
    }

    debug(
      `Successfully obtained token! Username: ${profile?.name ?? "unknown"}, UUID: ${profile?.id ?? "unknown"}`
    );

    return {
      accessToken: capturedToken,
      username: profile?.name,
      uuid: profile?.id,
      expiresIn,
      obtainedOn,
    };
  } finally {
    debug("Closing browser instance...");
    await browser.close().catch(() => {});
  }
}

/**
 * Convenient alias to launch a browser, load cookies, and return the token
 */
export const getAccessTokenFromBrowser = authenticateWithBrowserCookies;
