import https from "https";
import { buildProxyUrl } from "./proxy";
import type { BrowserAuthOptions, BrowserAuthResult } from "./browser";
import { parseJwtPayload } from "../utils";

const { HttpsProxyAgent } = require("https-proxy-agent");
const { SocksProxyAgent } = require("socks-proxy-agent");

export interface MsauthCookieOptions extends BrowserAuthOptions {
  microsoftClientId?: string;
  microsoftRedirectUri?: string;
  microsoftScope?: string;
}

export function normalizeMsauthCookie(value: string): string {
  let token = value.trim().replace(/^(["'])(.*)\1$/, "$2");
  token = token.replace(/^__Host-MSAAUTHP=/i, "").replace(/^11-/, "");
  return token.replace(/\$$/, "").trim();
}

export function isMsauthCookie(value: string): boolean {
  return /^__Host-MSAAUTHP=/i.test(value.trim()) ||
    /^11-M\.[CR].*\$$/.test(value.trim());
}

/** Exchange an MSAAUTHP session cookie; OAuth refresh tokens use tokenAccess instead. */
export async function getAccessTokenFromMsauthCookie(
  value: string,
  options: MsauthCookieOptions = {}
): Promise<BrowserAuthResult> {
  const token = normalizeMsauthCookie(value);
  if (!/^M\.[CR][^\s;\r\n]+$/.test(token)) throw new Error("Invalid MSAAUTHP session cookie.");
  const proxy = buildProxyUrl(options.proxy);
  const agent = proxy ? (proxy.protocol === "http:" || proxy.protocol === "https:"
    ? new HttpsProxyAgent(proxy.url) : new SocksProxyAgent(proxy.url)) : undefined;
  const timeout = options.timeout ?? 45000;

  function request(url: string, headers: Record<string, string>, body?: unknown): Promise<{ status: number; location?: string; data: any }> {
    return new Promise((resolve, reject) => {
      const req = https.request(url, {
        method: body === undefined ? "GET" : "POST", agent,
        headers: { Accept: "application/json", ...(body === undefined ? {} : { "Content-Type": "application/json" }), ...headers },
        rejectUnauthorized: options.allowUnsafeProxyTls ? false : undefined,
      }, res => {
        let text = "";
        res.setEncoding("utf8");
        res.on("data", chunk => { text += chunk; });
        res.on("error", reject);
        res.on("end", () => {
          let data: any;
          try { data = JSON.parse(text); } catch { data = undefined; }
          resolve({ status: res.statusCode ?? 0, location: res.headers.location, data });
        });
      });
      req.on("error", reject);
      req.setTimeout(timeout, () => req.destroy(new Error("Authentication request timed out.")));
      req.end(body === undefined ? undefined : JSON.stringify(body));
    });
  }

  async function post(url: string, body: unknown, label: string) {
    const response = await request(url, {}, body);
    if (response.status < 200 || response.status >= 300) throw new Error(`${label} failed with HTTP ${response.status}.`);
    if (!response.data) throw new Error(`${label} returned invalid JSON.`);
    return response.data;
  }

  const authorize = new URL("https://login.live.com/oauth20_authorize.srf");
  authorize.search = new URLSearchParams({
    client_id: options.microsoftClientId || "00000000402b5328",
    redirect_uri: options.microsoftRedirectUri || "https://login.live.com/oauth20_desktop.srf",
    scope: options.microsoftScope || "service::user.auth.xboxlive.com::MBI_SSL",
    response_type: "token", prompt: "none",
  }).toString();
  try {
    const response = await request(authorize.toString(), { Cookie: `__Host-MSAAUTHP=11-${token}$` });
    if (response.status < 300 || response.status >= 400 || !response.location) {
      throw new Error(`Microsoft cookie authorization returned HTTP ${response.status} without a token redirect.`);
    }
    const redirect = new URL(response.location, authorize);
    const fields = new URLSearchParams(redirect.hash.slice(1));
    const msToken = fields.get("access_token");
    if (!msToken) throw new Error("Microsoft cookie authorization did not return an access token. Sign in with the issuing application to renew the session and grant any requested consent. For an OAuth refresh token, use the refresh-token flow with its original client ID.");
    const xbl = await post("https://user.auth.xboxlive.com/user/authenticate", {
      Properties: { AuthMethod: "RPS", SiteName: "user.auth.xboxlive.com", RpsTicket: /^[dt]=/.test(msToken) ? msToken : `t=${msToken}` },
      RelyingParty: "http://auth.xboxlive.com", TokenType: "JWT",
    }, "Xbox Live authentication");
    const userHash = xbl.DisplayClaims?.xui?.[0]?.uhs;
    if (!xbl.Token || !userHash) throw new Error("Xbox Live response was missing token or user hash.");
    const xsts = await post("https://xsts.auth.xboxlive.com/xsts/authorize", {
      Properties: { SandboxId: "RETAIL", UserTokens: [xbl.Token] },
      RelyingParty: "rp://api.minecraftservices.com/", TokenType: "JWT",
    }, "XSTS authorization");
    if (!xsts.Token) throw new Error("XSTS response was missing token.");
    const mc = await post("https://api.minecraftservices.com/authentication/login_with_xbox", {
      identityToken: `XBL3.0 x=${userHash};${xsts.Token}`,
    }, "Minecraft login");
    if (!mc.access_token) throw new Error("Minecraft response was missing access token.");
    const jwt = parseJwtPayload<{ pfd?: Array<{ type?: string; name?: string; id?: string }>; profiles?: { mc?: string } }>(mc.access_token);
    const profile = jwt?.pfd?.find(p => p.type === "mc");
    let username = profile?.name;
    let uuid = profile?.id || jwt?.profiles?.mc;
    if (options.fetchProfile !== false && (!username || !uuid)) {
      const result = await request("https://api.minecraftservices.com/minecraft/profile", { Authorization: `Bearer ${mc.access_token}` });
      if (result.status !== 200 || !result.data?.name || !result.data?.id) throw new Error(`Minecraft profile lookup failed with HTTP ${result.status}.`);
      username = result.data.name;
      uuid = result.data.id;
    }
    return { accessToken: mc.access_token, username, uuid, expiresIn: mc.expires_in ?? 86400, obtainedOn: Date.now() };
  } finally {
    agent?.destroy();
  }
}
