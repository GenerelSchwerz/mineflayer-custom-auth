import crypto from "crypto";
import path from "path";
import { LiveCacheEntry, MinecraftJavaCacheEntry, TokenManagerLike, XSTSTokenRequest } from "../types";
import { getJwtExpiry } from "../utils";
import type { BrowserAuthOptions } from "../cookies/browser";
import { DEFAULT_REFRESH_CLIENT_ID, exchangeDirectRefreshToken } from "./direct";
export { DEFAULT_REFRESH_CLIENT_ID } from "./direct";

const { Authflow, Titles } = require("prismarine-auth");
const debug = require("debug")("mineflayer-custom-auth:token-access");

type LiveTokenSetup = {
  readonly accessToken?: string;
  readonly refreshToken?: string;
};

export interface RefreshTokenOptions extends BrowserAuthOptions {
  microsoftRedirectUri?: string;
  microsoftScope?: string;
  profilesFolder?: string;
  flow?: "live" | "sisu";
  authTitle?: string;
  deviceType?: string;
  fetchProfile?: boolean;
  forceRefresh?: boolean;
}

export interface RefreshTokenResult {
  accessToken: string;
  refreshToken?: string;
  username?: string;
  uuid?: string;
  expiresIn?: number;
  obtainedOn: number;
}

function buildAccessToken(accessToken: string): MinecraftJavaCacheEntry {
  const obtainedOn = Date.now();
  const until = getJwtExpiry(accessToken) ?? obtainedOn + 86400 * 1000;

  return {
    mca: {
      access_token: accessToken,
      expires_in: Math.floor((until - obtainedOn) / 1000),
      obtainedOn,
      token_type: "Bearer",
    },
  };
}

export function buildJavaPatchedManager<T extends TokenManagerLike<MinecraftJavaCacheEntry>>(manager: T, accessToken: string): T {
  if (!accessToken) {
    throw new Error("Access token must be provided for accessToken authentication.");
  }

  const originalGetCached = manager.cache.getCached.bind(manager.cache);

  manager.cache.getCached = async () => {
    const cached = (await originalGetCached()) as MinecraftJavaCacheEntry;
    const obtainedOn = Date.now();
    const until = getJwtExpiry(accessToken) ?? obtainedOn + 86400 * 1000;
    const remaining = until - Date.now();

    if (remaining <= 1000) {
      throw new Error(`Provided accessToken ${accessToken.slice(0, 12)}... is expired.`);
    }

    return {
      ...cached,
      mca: buildAccessToken(accessToken).mca,
    };
  };

  return manager;
}

export function buildLivePatchedManager<T extends TokenManagerLike<LiveCacheEntry>>(manager: T, tokens: LiveTokenSetup): T {
  if (!tokens.accessToken && !tokens.refreshToken) {
    throw new Error("At least one of accessToken or refreshToken must be provided.");
  }

  const originalGetCached = manager.cache.getCached.bind(manager.cache);
  const obtainedOn = Date.now();
  let initialToken: string | undefined;
  let initialized = false;
  let replaced = false;

  manager.cache.getCached = async () => {
    const cached = (await originalGetCached()) as LiveCacheEntry;
    const currentToken = JSON.stringify(cached.token);
    if (!initialized) {
      initialToken = currentToken;
      initialized = true;
    } else if (currentToken !== initialToken) {
      replaced = true;
    }
    // Once the manager writes an exchange result, retain its tokens and lifetime.
    if (replaced) return cached;

    const ret: Required<LiveCacheEntry> = { token: {} as unknown as NonNullable<LiveCacheEntry["token"]> };

    if (cached.token != null) ret.token = { ...cached.token };

    if (tokens.accessToken || tokens.refreshToken) {
      if (tokens.accessToken) ret.token.access_token = tokens.accessToken;
      if (tokens.refreshToken) ret.token.refresh_token = tokens.refreshToken;

      // A refresh token is not an access token. Force an OAuth exchange first.
      if (!tokens.accessToken) delete (ret.token as Partial<typeof ret.token>).access_token;
      ret.token.expires_in = tokens.accessToken ? 86400 : 0;
      ret.token.obtainedOn = obtainedOn;
      ret.token.token_type = "Bearer";
    }

    return ret;
  };

  return manager;
}

/**
 * Exchange a Microsoft Live OAuth refresh token for a Minecraft Java access token
 *
 * @param refreshToken - Microsoft Live refresh token
 * @param options - Configuration options for the exchange flow
 * @returns Minecraft Java access token and player profile
 */
export async function getAccessTokenFromRefreshToken(
  refreshToken: string,
  options: RefreshTokenOptions = {}
): Promise<RefreshTokenResult> {
  if (typeof refreshToken !== "string" || !refreshToken.trim()) {
    throw new Error("A valid refresh token must be provided.");
  }
  // Allow a copied "RefreshToken: ..." line, without guessing its credential type
  // from opaque token prefixes or changing characters inside the token.
  refreshToken = refreshToken.trim().replace(/^refresh[_ -]?token\s*:\s*/i, "").trim().replace(/^(["'])(.*)\1$/, "$2").trim();
  if (!refreshToken || /\s/.test(refreshToken)) throw new Error("A valid refresh token must be provided.");

  const clientId = options.authTitle ?? (options.flow === "sisu" ? Titles.MinecraftNintendoSwitch : DEFAULT_REFRESH_CLIENT_ID);
  if (clientId === DEFAULT_REFRESH_CLIENT_ID && options.flow !== "sisu") {
    return exchangeDirectRefreshToken(refreshToken, options);
  }

  const profilesFolder = options.profilesFolder || path.join(process.cwd(), "cache");
  const accountId = "rt_" + crypto.createHash("sha1").update(JSON.stringify([
    refreshToken, clientId,
    options.flow ?? "live", options.deviceType ?? "Nintendo",
  ])).digest("hex").slice(0, 10);
  const authflow = new Authflow(
    accountId,
    profilesFolder,
    {
      flow: options.flow ?? "live",
      authTitle: clientId,
      deviceType: options.deviceType ?? "Nintendo",
      forceRefresh: options.forceRefresh ?? true,
    }
  );

  const originalGetCached = authflow.msa.cache.getCached.bind(authflow.msa.cache);
  buildLivePatchedManager(authflow.msa, { refreshToken });
  let latestRefreshToken = refreshToken;
  // Exchange explicitly so an OAuth rejection is not swallowed into device login.
  try {
    const refreshed = await authflow.msa.refreshTokens();
    if (!refreshed?.access_token) throw new Error("Microsoft returned no access token.");
    latestRefreshToken = refreshed.refresh_token || refreshToken;
    // prismarine-auth starts this write without awaiting it; wait before continuing.
    await authflow.msa.updateCache(refreshed);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown refresh error";
    throw new Error(`Microsoft OAuth refresh failed: ${message.split(refreshToken).join("[redacted]")}`);
  } finally {
    authflow.msa.cache.getCached = originalGetCached;
  }
  authflow.msa.authDeviceCode = async () => {
    throw new Error("Microsoft refresh failed; sign in again using the original OAuth client.");
  };

  debug("Exchanging refresh token for Minecraft Java access token...");
  const tokenRes = await authflow.getMinecraftJavaToken({
    fetchProfile: options.fetchProfile !== false,
  });

  if (!tokenRes?.token) {
    throw new Error("Failed to exchange refresh token for Minecraft Java token.");
  }

  const obtainedOn = Date.now();
  const until = getJwtExpiry(tokenRes.token) ?? obtainedOn + 86400 * 1000;
  const expiresIn = Math.max(0, Math.floor((until - obtainedOn) / 1000));

  return {
    accessToken: tokenRes.token,
    refreshToken: latestRefreshToken,
    username: tokenRes.profile?.name,
    uuid: tokenRes.profile?.id,
    expiresIn,
    obtainedOn,
  };
}
