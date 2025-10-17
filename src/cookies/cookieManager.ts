/**
 * Minecraft Authentication System
 *
 * This TypeScript application automates Minecraft account authentication by:
 * 1. Using Microsoft account cookies to authenticate
 * 2. Managing proxies for authentication requests
 * 3. Retrieving Minecraft access tokens
 * 4. Storing authentication data in cache files
 */

import puppeteer from "puppeteer";
import fs from "fs";
import path from "path";
import { generateCacheFileName } from "../utils";

// Import FileCache class from prismarine-auth
const FileCache = require("prismarine-auth/src/common/cache/FileCache");

const debug = require('debug')('mineflayer-custom-auth')

import {cookie} from './cookie'

/**
 * Interface for proxy configuration
 */
interface ProxyConfig {
  server: string;
  port: string;
  username: string;
  password: string;
}

/**
 * Interface for Minecraft authentication cache object
 */
interface MinecraftAuthCache {
  mca: {
    username: string;
    roles: string[];
    metadata: Record<string, unknown>;
    access_token: string;
    expires_in: number;
    token_type: string;
    obtainedOn: number;
  };
}

interface ProcessAccRes {
  success: boolean;
  fromCache: boolean;
  token?: string;
  error?: string;
}

/**
 * Class for handling Minecraft authentication
 */
class MinecraftAuthenticator {
  private readonly cachePath: string;
  private readonly cacheName: string;
  private readonly headless: boolean;
  private readonly executableName: string;

  /**
   * Constructor for MinecraftAuthenticator
   *
   * @param cachePath - Path to the cache directory
   * @param outputFilePath - Path to the output file for authenticated accounts
   */
  constructor(cachePath = path.join(__dirname, "cache"), headless = false, executableName = "", cacheName = "mca") {
    this.cachePath = cachePath;
    this.cacheName = cacheName;
    this.headless = headless;
    this.executableName = executableName;
    this.ensureCacheDirectory();
  }

  /**
   * Create cache directory if it doesn't exist
   */
  private ensureCacheDirectory(): void {
    if (!fs.existsSync(this.cachePath)) {
      fs.mkdirSync(this.cachePath, { recursive: true });
    }
  }

  /**
   * Clear the cache directory
   */
  public clearCache(username: string): void {
    const fileCache = new FileCache(generateCacheFileName(this.cachePath, this.cacheName, username));
    fileCache.reset();
  }

  /**
   * Parse a proxy string into its components
   *
   * @param proxyString - Proxy string in format "server:port:username:password"
   * @returns Parsed proxy configuration
   */
  private parseProxyString(proxyString: string): ProxyConfig {
    const [server, port, username, password] = proxyString.split(":");
    return { server, port, username, password };
  }

  /**
   * Extract access token from cookie string
   *
   * @param cookieString - String containing cookies
   * @returns Access token or empty string if not found
   */
  private extractAccessToken(cookieString: string): string {
    const bearerToken = "bearer_token=";
    const start = cookieString.indexOf(bearerToken) + bearerToken.length;
    if (start <= bearerToken.length) return "";

    const end = cookieString.indexOf(";", start);
    return end === -1 ? cookieString.substring(start) : cookieString.substring(start, end);
  }

  /**
   * Create Minecraft authentication cache object
   *
   * @param accessToken - Minecraft access token
   * @returns Minecraft authentication cache object
   */
  private createAuthCacheObject(accessToken: string): MinecraftAuthCache {
    return {
      mca: {
        // Username doesn't matter, was meant to be UUID originally
        username: "thisreallydoesntmatter",
        roles: [],
        metadata: {},
        // Access token used for authentication
        access_token: accessToken,
        // SSIDs expire every day, set to 86400 as a result
        expires_in: 86400,
        token_type: "Bearer",
        obtainedOn: Date.now(),
      },
    };
  }

  private async saveAuthCacheObject(cacheFile: typeof FileCache, authCache: MinecraftAuthCache) {
    // Save authentication cache using FileCache's setCachedPartial method (matching second file)
    debug('saving auth cache', authCache);
    await cacheFile.setCachedPartial({
      mca: {
        ...authCache.mca,
        obtainedOn: Date.now(),
      },
      cookie: true
    });
  }

  /**
   * Process a single Microsoft account with puppeteer
   *
   * @param referencedUsername - Username for cache file naming
   * @param cookieFilePath - Path to the cookie file
   * @param proxyConfig - Proxy configuration
   * @returns Promise resolving to an object containing success status and whether it came from cache
   */
  public async processAccount(
    referencedUsername: string,
    cookies: cookie.Cookie[],
    proxyConfig?: ProxyConfig | string
  ): Promise<ProcessAccRes> {
    // Extract file name without extension

    // First, check if we already have a valid cached token
    const cachedToken = await this.getCachedAccessToken(referencedUsername);
    if (cachedToken && cachedToken.valid) {
      debug(`✅ Already authenticated via cache: ${referencedUsername}`);
      // Still add to alts.txt to ensure it's listed
      return {
        success: true,
        fromCache: true,
        token: cachedToken.token,
      };
    }

    debug(`No valid cached token found, authenticating: ${referencedUsername}`);

    // Parse proxy if string is provided
    const proxy = typeof proxyConfig === "string" ? this.parseProxyString(proxyConfig) : proxyConfig;

    try {

      const name = generateCacheFileName(this.cachePath, this.cacheName, referencedUsername)

      // Create a FileCache instance for storing authentication data
      const cacheFile = new FileCache(name);


      if (cookies.length === 0) {
        debug(`No valid cookies found in ${cacheFile.filePath}`);
        return {
          success: false,
          fromCache: false,
        };
      }

      const args = [];
      let proxyUrl = null;
      if (proxy != null) {
        // Configure proxy URL

        if (!proxy.username && !proxy.password) {
          proxyUrl = new URL(`http://${proxy.server}:${proxy.port}`);
        } else {
          proxyUrl = new URL(`http://${proxy.username}:${proxy.password}@${proxy.server}:${proxy.port}`);
        }
        args.push(`--proxy-server=${proxyUrl.host}`);
      }

      // Launch browser with proxy
      const browser = await puppeteer.launch({
        args,
        executablePath: this.executableName || undefined,
        headless: this.headless,
      });

      const page = await browser.newPage();

      if (proxyUrl != null && proxyUrl.username && proxyUrl.password) {
        // Authenticate with proxy
        await page.authenticate({
          username: proxyUrl.username,
          password: proxyUrl.password,
        });
      }

      // Set user agent to avoid detection
      await page.setUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0");

      try {
        // Clear existing cookies
        const context = page.browserContext();
        const pageCookies = await context.cookies();
        for (const cookie of pageCookies) {
          await context.deleteCookie(cookie);
        }

        // Check if we have Microsoft login cookies
        const hasMicrosoftCookies = cookies.some(
          (cookie) => cookie.domain === ".live.com" || cookie.domain === "login.live.com" || cookie.domain === ".login.live.com"
        );

        if (hasMicrosoftCookies) {
          // Navigate to login page first
          await page.goto("https://login.live.com", { waitUntil: "networkidle0" });
          // Set our cookies
          for (const cookie of cookies) {
            try {
              await context.setCookie(cookie);
            } catch (error) {
              debug(`Error setting cookie for ${referencedUsername}:`, error);
            }
          }
        } else {
          debug(`Warning: No Microsoft login cookies found for ${referencedUsername}`);
        }

        // Authentication process
        await page.goto("https://login.live.com", { waitUntil: "networkidle0" });
        await page.reload({ waitUntil: "networkidle0" });
        await page.goto("https://www.minecraft.net/en-us/login", { waitUntil: "networkidle0" });

        // Click Microsoft login button
        const msaButton = '[data-testid="MSALoginButtonLink"]';
        await page.waitForSelector(msaButton);
        await page.click(msaButton);

        // Wait for login process
        await new Promise((resolve) => setTimeout(resolve, 3000));

        // Navigate to profile page to get authentication token
        await page.goto("https://www.minecraft.net/en-us/msaprofile/mygames", { waitUntil: "networkidle0" });

        // Extract access token from cookies
        const cookieString = await page.evaluate(() => document.cookie);
        const accessToken = this.extractAccessToken(cookieString);

        if (accessToken.startsWith("ey")) {
          debug(`✅ Successfully authenticated: ${referencedUsername}`);

          // Create authentication cache object
          const authCache = this.createAuthCacheObject(accessToken);
          await this.saveAuthCacheObject(cacheFile, authCache);

          return {
            success: true,
            fromCache: false,
            token: accessToken,
          };
        } else {
          debug(`❌ Authentication failed for ${referencedUsername} - Invalid or locked account`);
          debug(`Extracted token: ${accessToken}`);
          return {
            success: false,
            fromCache: false,
          };
        }
      } finally {
        await browser.close();
      }
    } catch (error) {
      console.error(`Error processing account ${referencedUsername}:`, error);
      return {
        success: false,
        fromCache: false,
        error: (error as Error).message,
      };
    }
  }

  /**
   * Get cached access token (matching the second file's implementation)
   *
   * @param referencedUsername - Username for cache file naming
   * @returns Cached access token information or undefined if not found/invalid
   */
  public async getCachedAccessToken(referencedUsername: string, onlyCookieStorage=true) {
    // Create a FileCache instance for retrieving authentication data
    const cacheFile = new FileCache(generateCacheFileName(this.cachePath, this.cacheName, referencedUsername));

    try {
      const { mca: token, cookie } = await cacheFile.getCached();
      debug("token cache", token, 'is from cookie:', !!cookie);
      if (!token || (onlyCookieStorage && !cookie)) return;

      const expires = token.obtainedOn + token.expires_in * 1000;
      const remaining = expires - Date.now();
      const valid = remaining > 1000;

      return { is_cookie: !!cookie, valid, until: expires, token: token.access_token, data: token };
    } catch (error) {
      console.error("Error getting cached access token:", error);
      return undefined;
    }
  }

  /**
   * Get the usable token for a referenced username, either from cache or by authenticating
   *
   * @param referencedUsername - Username for cache file naming
   * @param cookieFilePath - Path to the cookie file
   * @param proxyConfig - Optional proxy configuration
   * @returns The authentication token if successful
   */
  public async getToken(referencedUsername: string, cookies: cookie.Cookie[], proxyConfig?: ProxyConfig | string) {
    const result = await this.processAccount(referencedUsername, cookies, proxyConfig);
    if (result.success) {
      return result.token;
    }
    throw new Error(result.fromCache ? "Failed to get token from cache" : "Failed to authenticate with provided credentials");
  }
}

// Export the class
export { MinecraftAuthenticator };
