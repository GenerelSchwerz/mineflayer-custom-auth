export {
  BrowserCookieAuthenticator,
  BrowserlessCookieAuthenticator,
  CookieCacheManager,
  createCookieAuthenticator,
  MinecraftAuthenticator,
  authenticateWithBrowserCookies,
  getAccessTokenFromBrowser,
  type BrowserAuthResult,
  type BrowserAuthOptions,
} from "./cookies/cookieManager";

export {
  getAccessTokenFromRefreshToken,
  DEFAULT_REFRESH_CLIENT_ID,
  buildLivePatchedManager,
  buildJavaPatchedManager,
  buildJavaPatchedManager as buildPatchedManager,
  type RefreshTokenOptions,
  type RefreshTokenResult,
} from "./tokenAccess";

export {
  getAccessToken,
  getMinecraftToken,
  type UnifiedAuthOptions,
  type UnifiedAuthResult,
  type TokenInput,
} from "./unified";

export { getAccessTokenFromMsauthCookie, type MsauthCookieOptions } from "./cookies/msauth";

import { cookie } from "./cookies/cookie";
import type { ClientOptions } from "minecraft-protocol";

import "mineflayer";
import { CookieOptions } from "./types";

declare module "mineflayer" {
  interface BotOptions {
    auth?: ClientOptions["auth"] | "cookies" | "accessToken" | "refreshToken" | "auto";
    cookieOptions?: CookieOptions;
    cookieFile?: string;
    refreshToken?: string;
    accessToken?: string;
  }
}

declare module "minecraft-protocol" {
  interface ClientOptions {
    flow?: "live" | "sisu" | "msal";
    deviceType?: string;
    javaAccessToken?: string;
    liveAccessToken?: string;
    liveRefreshToken?: string;
  }
}

export type { CookieAuthMethod, CookieOptions, ProxyConfig, MinecraftAuthCache } from "./types";
export { createBot } from "./impl";
export { cookie } from "./cookies/cookie";
