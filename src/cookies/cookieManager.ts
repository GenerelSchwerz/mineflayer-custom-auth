/**
 * Minecraft Authentication System
 *
 * This module keeps the browser and browserless cookie auth paths separate.
 * They share cache/proxy helpers, but each authenticator owns one execution path.
 */

import fs from "fs";
import path from "path";
import crypto from "crypto";
import { generateCacheFileName, getJwtExpiry } from "../utils";
import { cookie } from "./cookie";
import type { CookieAuthMethod, CookieOptions, MinecraftAuthCache, ProxyConfig } from "../types";
import { authenticateWithBrowserlessCookies } from "./browserless";
import { authenticateWithBrowserCookies, getAccessTokenFromBrowser, BrowserAuthResult, BrowserAuthOptions } from "./browser";

const FileCache = require("prismarine-auth/src/common/cache/FileCache");
const debug = require("debug")("mineflayer-custom-auth");

function fingerprintCookies(cookies: cookie.Cookie[]): string {
  // Ignore parser-generated expiry defaults; include every cookie's identity and value.
  const values = cookies.map(c => JSON.stringify([c.domain, c.path || "/", c.name, c.value])).sort();
  return crypto.createHash("sha256").update(JSON.stringify(values)).digest("hex");
}

export interface ProcessAccRes {
  success: boolean;
  fromCache: boolean;
  token?: string;
  error?: string;
}

type CachedTokenResult = {
  is_cookie: boolean;
  valid: boolean;
  until: number;
  token: string;
  data: MinecraftAuthCache["mca"];
};

export interface CookieAuthenticator {
  processAccount(
    referencedUsername: string,
    cookies: cookie.Cookie[] | string | string[],
    proxyConfig?: ProxyConfig | string
  ): Promise<ProcessAccRes>;
  getToken(
    referencedUsername: string,
    cookies: cookie.Cookie[] | string | string[],
    proxyConfig?: ProxyConfig | string
  ): Promise<string | undefined>;
}

export class CookieCacheManager {
  protected readonly cachePath: string;
  protected readonly cacheName: string;

  constructor(cachePath = path.join(__dirname, "cache"), cacheName = "mca") {
    this.cachePath = cachePath;
    this.cacheName = cacheName;
    this.ensureCacheDirectory();
  }

  protected ensureCacheDirectory(): void {
    if (!fs.existsSync(this.cachePath)) {
      fs.mkdirSync(this.cachePath, { recursive: true });
    }
  }

  protected getCacheFile(username: string): typeof FileCache {
    return new FileCache(generateCacheFileName(this.cachePath, this.cacheName, username));
  }

  public clearCache(username: string): void {
    this.getCacheFile(username).reset();
  }

  public async getCachedAccessToken(referencedUsername: string, onlyCookieStorage = true, inputFingerprint?: string): Promise<CachedTokenResult | undefined> {
    try {
      const { mca: token, cookie: isCookie, cookie_input_hash: storedFingerprint } = await this.getCacheFile(referencedUsername).getCached();
      if (inputFingerprint && storedFingerprint !== inputFingerprint) return;
      debug("token cache present:", !!token, "is from cookie:", !!isCookie);
      if (!token || (onlyCookieStorage && !isCookie)) return;

      const expires = token.obtainedOn + token.expires_in * 1000;
      const remaining = expires - Date.now();
      const valid = remaining > 1000;

      return { is_cookie: !!isCookie, valid, until: expires, token: token.access_token, data: token };
    } catch (error) {
      console.error("Error getting cached access token:", error);
      return undefined;
    }
  }

  protected createAuthCacheObject(accessToken: string, username = "thisreallydoesntmatter"): MinecraftAuthCache {
    const obtainedOn = Date.now();
    return {
      mca: {
        username,
        roles: [],
        metadata: {},
        access_token: accessToken,
        expires_in: Math.max(0, Math.floor(((getJwtExpiry(accessToken) ?? obtainedOn + 86400000) - obtainedOn) / 1000)),
        token_type: "Bearer",
        obtainedOn,
      },
    };
  }

  protected async saveAuthCacheObject(cacheFile: typeof FileCache, authCache: MinecraftAuthCache, inputFingerprint?: string) {
    debug("saving auth cache");
    await cacheFile.setCachedPartial({
      mca: {
        ...authCache.mca,
        obtainedOn: Date.now(),
      },
      cookie: true,
      cookie_input_hash: inputFingerprint,
    });
  }
}

abstract class BaseCookieAuthenticator extends CookieCacheManager implements CookieAuthenticator {
  protected async getCachedProcessResult(referencedUsername: string, inputFingerprint: string): Promise<ProcessAccRes | undefined> {
    const cachedToken = await this.getCachedAccessToken(referencedUsername, true, inputFingerprint);
    if (!cachedToken?.valid) return undefined;

    debug(`Already authenticated via cache: ${referencedUsername}`);
    return {
      success: true,
      fromCache: true,
      token: cachedToken.token,
    };
  }

  protected validateCookies(cacheFileName: string, cookies: cookie.Cookie[]): ProcessAccRes | undefined {
    if (cookies.length !== 0) return undefined;

    debug(`No valid cookies found in ${cacheFileName}`);
    return {
      success: false,
      fromCache: false,
    };
  }

  public abstract processAccount(
    referencedUsername: string,
    cookies: cookie.Cookie[] | string | string[],
    proxyConfig?: ProxyConfig | string
  ): Promise<ProcessAccRes>;

  public async getToken(
    referencedUsername: string,
    cookies: cookie.Cookie[] | string | string[],
    proxyConfig?: ProxyConfig | string
  ) {
    const result = await this.processAccount(referencedUsername, cookies, proxyConfig);
    if (result.success) return result.token;

    throw new Error(result.fromCache ? "Failed to get token from cache" : (result.error ?? "Failed to authenticate with provided credentials"));
  }
}

export class BrowserlessCookieAuthenticator extends BaseCookieAuthenticator {
  private readonly allowUnsafeProxyTls: boolean;
  private readonly options: Pick<CookieOptions, "timeout" | "fetchProfile" | "microsoftClientId" | "microsoftRedirectUri" | "microsoftScope">;

  constructor(cachePath = path.join(__dirname, "cache"), cacheName = "mca", allowUnsafeProxyTls = false, options: Pick<CookieOptions, "timeout" | "fetchProfile" | "microsoftClientId" | "microsoftRedirectUri" | "microsoftScope"> = {}) {
    super(cachePath, cacheName);
    this.allowUnsafeProxyTls = allowUnsafeProxyTls;
    this.options = options;
  }

  public async processAccount(
    referencedUsername: string,
    cookiesInput: cookie.Cookie[] | string | string[],
    proxyConfig?: ProxyConfig | string
  ): Promise<ProcessAccRes> {
    const cookies = cookie.loadCookies(cookiesInput);
    const inputFingerprint = fingerprintCookies(cookies);
    const cachedResult = await this.getCachedProcessResult(referencedUsername, inputFingerprint);
    if (cachedResult) return cachedResult;

    const cacheFile = this.getCacheFile(referencedUsername);
    const validationError = this.validateCookies(generateCacheFileName(this.cachePath, this.cacheName, referencedUsername), cookies);
    if (validationError) return validationError;

    try {
      const result = await authenticateWithBrowserlessCookies(cookies, proxyConfig, {
        ...this.options,
        allowUnsafeProxyTls: this.allowUnsafeProxyTls,
      });
      if (!result?.accessToken) {
        debug(`Browserless cookie authentication did not produce a token for ${referencedUsername}`);
        return {
          success: false,
          fromCache: false,
        };
      }

      debug(`Successfully authenticated via browserless cookies: ${referencedUsername} (${result.username})`);
      await this.saveAuthCacheObject(cacheFile, this.createAuthCacheObject(result.accessToken, result.uuid), inputFingerprint);

      return {
        success: true,
        fromCache: false,
        token: result.accessToken,
      };
    } catch (error) {
      debug(`Browserless cookie authentication failed for ${referencedUsername}:`, error);
      return {
        success: false,
        fromCache: false,
        error: (error as Error).message,
      };
    }
  }
}

export class BrowserCookieAuthenticator extends BaseCookieAuthenticator {
  private readonly headless: boolean;
  private readonly executableName: string;
  private readonly allowUnsafeProxyTls: boolean;
  private readonly timeout?: number;
  private readonly fetchProfile?: boolean;

  constructor(
    cachePath = path.join(__dirname, "cache"),
    headless = true,
    executableName = "",
    cacheName = "mca",
    allowUnsafeProxyTls = false,
    timeout?: number,
    fetchProfile = true
  ) {
    super(cachePath, cacheName);
    this.headless = headless;
    this.executableName = executableName;
    this.allowUnsafeProxyTls = allowUnsafeProxyTls;
    this.timeout = timeout;
    this.fetchProfile = fetchProfile;
  }

  public async processAccount(
    referencedUsername: string,
    cookiesInput: cookie.Cookie[] | string | string[],
    proxyConfig?: ProxyConfig | string
  ): Promise<ProcessAccRes> {
    const cookies = cookie.loadCookies(cookiesInput);
    const inputFingerprint = fingerprintCookies(cookies);
    const cachedResult = await this.getCachedProcessResult(referencedUsername, inputFingerprint);
    if (cachedResult) return cachedResult;

    const cacheFile = this.getCacheFile(referencedUsername);
    const validationError = this.validateCookies(generateCacheFileName(this.cachePath, this.cacheName, referencedUsername), cookies);
    if (validationError) return validationError;

    try {
      const result = await authenticateWithBrowserCookies(cookies, {
        headless: this.headless,
        executablePath: this.executableName,
        proxy: proxyConfig,
        allowUnsafeProxyTls: this.allowUnsafeProxyTls,
        timeout: this.timeout,
        fetchProfile: this.fetchProfile,
      });

      if (!result?.accessToken) {
        debug(`Browser cookie authentication did not produce a token for ${referencedUsername}`);
        return {
          success: false,
          fromCache: false,
        };
      }

      debug(`Successfully authenticated via browser cookies: ${referencedUsername} (${result.username ?? "unknown"})`);
      await this.saveAuthCacheObject(cacheFile, this.createAuthCacheObject(result.accessToken, result.uuid ?? referencedUsername), inputFingerprint);

      return {
        success: true,
        fromCache: false,
        token: result.accessToken,
      };
    } catch (error) {
      debug(`Browser cookie authentication failed for ${referencedUsername}:`, error);
      return {
        success: false,
        fromCache: false,
        error: (error as Error).message,
      };
    }
  }
}

class AutoCookieAuthenticator extends CookieCacheManager implements CookieAuthenticator {
  private readonly browserless: BrowserlessCookieAuthenticator;
  private readonly browser: BrowserCookieAuthenticator;

  constructor(
    cachePath = path.join(__dirname, "cache"),
    headless = true,
    executableName = "",
    cacheName = "mca",
    allowUnsafeProxyTls = false,
    timeout?: number,
    fetchProfile = true,
    microsoftOptions: Pick<CookieOptions, "microsoftClientId" | "microsoftRedirectUri" | "microsoftScope"> = {}
  ) {
    super(cachePath, cacheName);
    this.browserless = new BrowserlessCookieAuthenticator(cachePath, cacheName, allowUnsafeProxyTls, { timeout, fetchProfile, ...microsoftOptions });
    this.browser = new BrowserCookieAuthenticator(
      cachePath,
      headless,
      executableName,
      cacheName,
      allowUnsafeProxyTls,
      timeout,
      fetchProfile
    );
  }

  public async processAccount(
    referencedUsername: string,
    cookies: cookie.Cookie[] | string | string[],
    proxyConfig?: ProxyConfig | string
  ) {
    const browserlessResult = await this.browserless.processAccount(referencedUsername, cookies, proxyConfig);
    if (browserlessResult.success) return browserlessResult;

    debug(`Browserless auth failed for ${referencedUsername}; trying browser auth`);
    return this.browser.processAccount(referencedUsername, cookies, proxyConfig);
  }

  public async getToken(
    referencedUsername: string,
    cookies: cookie.Cookie[] | string | string[],
    proxyConfig?: ProxyConfig | string
  ) {
    const result = await this.processAccount(referencedUsername, cookies, proxyConfig);
    if (result.success) return result.token;

    throw new Error(result.fromCache ? "Failed to get token from cache" : (result.error ?? "Failed to authenticate with provided credentials"));
  }
}

export function createCookieAuthenticator(
  authMethod: CookieAuthMethod = "auto",
  cachePath = path.join(__dirname, "cache"),
  headless = true,
  executableName = "",
  cacheName = "mca",
  options: Pick<CookieOptions, "allowUnsafeProxyTls" | "timeout" | "fetchProfile" | "microsoftClientId" | "microsoftRedirectUri" | "microsoftScope"> = {}
): CookieAuthenticator {
  switch (authMethod) {
    case "browserless":
      return new BrowserlessCookieAuthenticator(cachePath, cacheName, options.allowUnsafeProxyTls ?? false, options);
    case "browser":
      return new BrowserCookieAuthenticator(
        cachePath,
        headless,
        executableName,
        cacheName,
        options.allowUnsafeProxyTls ?? false,
        options.timeout,
        options.fetchProfile
      );
    case "auto":
      return new AutoCookieAuthenticator(
        cachePath,
        headless,
        executableName,
        cacheName,
        options.allowUnsafeProxyTls ?? false,
        options.timeout,
        options.fetchProfile,
        options
      );
  }
}

export {
  BrowserCookieAuthenticator as MinecraftAuthenticator,
  authenticateWithBrowserCookies,
  getAccessTokenFromBrowser,
  type BrowserAuthResult,
  type BrowserAuthOptions,
};
