import fs from "fs";
import { cookie } from "./cookies/cookie";
import {
  getAccessTokenFromBrowser,
  BrowserAuthOptions,
  BrowserAuthResult,
} from "./cookies/browser";
import {
  getAccessTokenFromRefreshToken,
  RefreshTokenOptions,
} from "./tokenAccess";
import { getJwtExpiry, parseJwtPayload } from "./utils";
import { getAccessTokenFromMsauthCookie, isMsauthCookie, MsauthCookieOptions } from "./cookies/msauth";
import { authenticateWithBrowserlessCookies } from "./cookies/browserless";

export interface UnifiedAuthOptions extends BrowserAuthOptions, RefreshTokenOptions, MsauthCookieOptions {
  msauthCookie?: string;
  cookieFile?: string;
  cookies?: cookie.Cookie[] | string | string[];
  refreshToken?: string;
  liveRefreshToken?: string;
  accessToken?: string;
  javaAccessToken?: string;
  authMethod?: "auto" | "browser" | "browserless";
}

export interface UnifiedAuthResult extends BrowserAuthResult {
  /** Updated OAuth refresh token, when the input used OAuth refresh authentication. */
  refreshToken?: string;
}

export type TokenInput =
  | string
  | cookie.Cookie[]
  | {
      msauthCookie?: string;
      cookieFile?: string;
      cookies?: cookie.Cookie[] | string | string[];
      refreshToken?: string;
      liveRefreshToken?: string;
      accessToken?: string;
      javaAccessToken?: string;
      [key: string]: unknown;
    };

/**
 * Check if a string looks like raw cookie content
 */
function isCookieContent(content: string): boolean {
  const trimmed = content.trim();
  if ((trimmed.startsWith("[") || trimmed.startsWith("{")) && trimmed.includes('"name"') && trimmed.includes('"value"')) {
    return true; // JSON cookies
  }
  if (trimmed.includes("\t") && trimmed.split("\n").some((l) => l.split("\t").length >= 7)) {
    return true; // Netscape / TSV cookies
  }
  if (
    trimmed.includes("MSPAuth=") ||
    trimmed.includes("__Host-MSAAUTH=") ||
    trimmed.includes("__Host-MSAAUTHP=") ||
    trimmed.includes("PPLState=")
  ) {
    return true; // Header format cookies
  }
  return false;
}

async function authenticateCookies(source: cookie.Cookie[] | string | string[], options: UnifiedAuthOptions): Promise<BrowserAuthResult> {
  const cookies = cookie.loadCookies(source);
  if (!cookies.length) throw new Error("No cookies found in the supplied cookie input.");
  if (options.authMethod !== "browser") {
    options.onStatus?.("Attempting silent (browserless) cookie authentication...");
    try {
      const result = await authenticateWithBrowserlessCookies(cookies, options.proxy, options);
      if (result?.accessToken) {
        options.onStatus?.("Silent authentication succeeded!");
        const obtainedOn = Date.now();
        return { ...result, obtainedOn, expiresIn: Math.max(0, Math.floor(((getJwtExpiry(result.accessToken) ?? obtainedOn + 86400000) - obtainedOn) / 1000)) };
      }
      if (options.authMethod === "browserless") throw new Error("Browserless cookie authentication did not return an access token.");
      options.onStatus?.("Silent authentication could not obtain a token (interactive login or full browser required).");
    } catch (error) {
      if (options.authMethod === "browserless") throw error;
      options.onStatus?.(`Silent authentication failed (${error instanceof Error ? error.message : String(error)}). Falling back to browser automation...`);
    }
  }
  options.onStatus?.(`Launching ${options.headless === false ? "visible" : "headless"} browser automation...`);
  return getAccessTokenFromBrowser(cookies, options);
}

function extractJwtResult(token: string): BrowserAuthResult {
  const jwt = parseJwtPayload<Record<string, unknown>>(token);
  const exp = typeof jwt?.exp === "number" ? jwt.exp * 1000 : undefined;
  const pfdArray = Array.isArray(jwt?.pfd) ? (jwt.pfd as Array<{ type?: string; id?: string; name?: string }>) : [];
  const mcProfile = pfdArray.find((p) => p && p.type === "mc");
  const username = mcProfile?.name;
  const uuid = mcProfile?.id || (jwt?.profiles && typeof (jwt.profiles as Record<string, string>).mc === "string" ? (jwt.profiles as Record<string, string>).mc : undefined);
  const obtainedOn = typeof jwt?.iat === "number" ? jwt.iat * 1000 : Date.now();
  const expiresIn = exp ? Math.max(0, Math.floor((exp - Date.now()) / 1000)) : 86400;

  return {
    accessToken: token,
    username,
    uuid,
    expiresIn,
    obtainedOn,
  };
}

/**

 * Universal token getter supporting both cookie files/data and OAuth refresh tokens.
 *
 * Examples:
 * ```ts
 * // 1. Pass cookie file path:
 * const res = await getAccessToken("./cookies.txt");
 *
 * // 2. Pass Microsoft Live refresh token:
 * const res = await getAccessToken("M.R3_BL2...");
 *
 * // 3. Pass options object:
 * const res = await getAccessToken({ cookieFile: "./cookies.txt", headless: false });
 * ```
 */
export async function getAccessToken(
  input: TokenInput,
  options: UnifiedAuthOptions = {}
): Promise<UnifiedAuthResult> {
  if (!input) {
    throw new Error("No token or cookie input provided.");
  }
  if (Array.isArray(input)) return authenticateCookies(input, options);

  // Case 1: Options object passed
  if (typeof input === "object") {
    const mergedOptions: UnifiedAuthOptions = { ...options, ...input };

    if (mergedOptions.msauthCookie) return getAccessTokenFromMsauthCookie(mergedOptions.msauthCookie, mergedOptions);

    const cookieSource = mergedOptions.cookieFile ?? mergedOptions.cookies;
    if (cookieSource) {
      if (mergedOptions.cookieFile && (!fs.existsSync(mergedOptions.cookieFile) || !fs.statSync(mergedOptions.cookieFile).isFile())) {
        throw new Error("Cookie file does not exist or is not a file.");
      }
      return authenticateCookies(cookieSource, mergedOptions);
    }

    const refreshSource = mergedOptions.refreshToken ?? mergedOptions.liveRefreshToken;
    if (refreshSource) {
      return getAccessTokenFromRefreshToken(refreshSource, mergedOptions);
    }

    const accessSource = mergedOptions.accessToken ?? mergedOptions.javaAccessToken;
    if (accessSource) {
      return extractJwtResult(accessSource);
    }

    throw new Error("Options object must specify 'cookieFile', 'cookies', 'msauthCookie', 'refreshToken', or 'accessToken'.");
  }

  // Case 2: String input (could be file path, raw cookies, JWT, or refresh token)
  const trimmed = input.trim().replace(/^(["'])(.*)\1$/, "$2");
  if (!trimmed) throw new Error("No token or cookie input provided.");

  // 2a. Check if it's an existing file on disk
  if (fs.existsSync(trimmed)) {
    if (!fs.statSync(trimmed).isFile()) throw new Error("Input path must be a file.");
    const fileContent = fs.readFileSync(trimmed, "utf8").trim();
    return authenticateContent(fileContent, options);
  }

  if (/^(?:[a-z]:[\\/]|\.{1,2}[\\/]|[\\/])/i.test(trimmed) || /\.(?:txt|json)$/i.test(trimmed)) {
    throw new Error("Input file does not exist.");
  }
  return authenticateContent(trimmed, options);
}

async function authenticateContent(trimmed: string, options: UnifiedAuthOptions): Promise<UnifiedAuthResult> {
  trimmed = trimmed.trim().replace(/^(["'])(.*)\1$/, "$2");
  if (!trimmed) throw new Error("Input file or token is empty.");

  // Inspect content instead of guessing from the file extension.
  if (isCookieContent(trimmed)) return authenticateCookies(trimmed, options);
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    let parsed;
    try { parsed = JSON.parse(trimmed); } catch { throw new Error("Invalid JSON input."); }
    const account = Array.isArray(parsed) ? (parsed.length === 1 ? parsed[0] : undefined) : parsed;
    const token = account?.refresh_token ?? account?.refreshToken ?? account?.token;
    if (typeof token !== "string" || !token.trim()) throw new Error("JSON input must contain cookies or a single token record.");
    if (account.refresh_token !== undefined || account.refreshToken !== undefined) return getAccessTokenFromRefreshToken(token, options);
    return authenticateContent(token, options);
  }
  const annotated = trimmed.match(/^#\s*refresh[_-]?token\s*:\s*(\S+)/im);
  if (annotated) return getAccessTokenFromRefreshToken(annotated[1], options);
  if (isMsauthCookie(trimmed)) return getAccessTokenFromMsauthCookie(trimmed, options);

  // 2b. Check if string is a raw JWT access token
  if (trimmed.startsWith("ey") && trimmed.split(".").length === 3) {
    return extractJwtResult(trimmed);
  }

  // 2d. Default: Treat as refresh token string
  return getAccessTokenFromRefreshToken(trimmed, options);
}

export const getMinecraftToken = getAccessToken;
