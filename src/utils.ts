import path from 'path'
const { createHash } = require("prismarine-auth/src/common/Util");


/**
 * Generate cache file name for a given username
 */
export function generateCacheFileName(pathName: string, cacheName: string, username: string): string {
  return  path.join(pathName,`${createHash(username)}_${cacheName}-cache.json`)
}


export function parseJwtPayload<T = Record<string, unknown>>(accessToken: string): T | undefined {
  const [, payload] = accessToken.split(".");
  if (!payload) return;

  try {
    const normalizedPayload = payload.replace(/-/g, "+").replace(/_/g, "/");
    const paddedPayload = normalizedPayload.padEnd(Math.ceil(normalizedPayload.length / 4) * 4, "=");
    const decodedPayload = Buffer.from(paddedPayload, "base64").toString("utf8");
    return JSON.parse(decodedPayload) as T;
  } catch {
    return undefined;
  }
}

export function getJwtExpiry(accessToken: string): number | undefined {
  const payload = parseJwtPayload<{ exp?: unknown }>(accessToken);
  return typeof payload?.exp === "number" ? payload.exp * 1000 : undefined;
}

