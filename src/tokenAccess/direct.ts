import https from "https";
import { buildProxyUrl } from "../cookies/proxy";
import { parseJwtPayload } from "../utils";
import type { BrowserAuthOptions } from "../cookies/browser";
import type { RefreshTokenResult } from "./index";

const { HttpsProxyAgent } = require("https-proxy-agent");
const { SocksProxyAgent } = require("socks-proxy-agent");

// The OAuth client used by the original standalone refresh script.
export const DEFAULT_REFRESH_CLIENT_ID = "00000000402b5328";

interface DirectRefreshOptions extends BrowserAuthOptions {
  microsoftRedirectUri?: string;
  microsoftScope?: string;
}

/** Desktop Live OAuth tokens use user/XSTS auth, without Nintendo device/title auth. */
export async function exchangeDirectRefreshToken(token: string, options: DirectRefreshOptions = {}): Promise<RefreshTokenResult> {
  const proxy = buildProxyUrl(options.proxy);
  const agent = proxy ? (proxy.protocol === "http:" || proxy.protocol === "https:"
    ? new HttpsProxyAgent(proxy.url) : new SocksProxyAgent(proxy.url)) : undefined;
  const timeout = options.timeout ?? 45000;

  function request(url: string, label: string, body?: string | object, headers: Record<string, string> = {}): Promise<any> {
    return new Promise((resolve, reject) => {
      const req = https.request(url, {
        method: body === undefined ? "GET" : "POST", agent,
        headers: {
          "User-Agent": options.userAgent || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
          Accept: "application/json",
          ...(body === undefined ? {} : { "Content-Type": typeof body === "string" ? "application/x-www-form-urlencoded" : "application/json" }),
          ...headers,
        },
        rejectUnauthorized: options.allowUnsafeProxyTls ? false : undefined,
      }, response => {
        let text = "";
        response.setEncoding("utf8");
        response.on("data", chunk => { text += chunk; });
        response.on("error", reject);
        response.on("aborted", () => reject(new Error(`${label} response was interrupted.`)));
        response.on("end", () => {
          let data;
          try { data = JSON.parse(text); } catch { data = undefined; }
          const status = response.statusCode ?? 0;
          if (status < 200 || status >= 300) {
            // Preserve useful OAuth diagnostics without printing credentials or token responses.
            const detail = label === "Microsoft OAuth refresh" && typeof data?.error_description === "string"
              ? ": " + data.error_description.split(token).join("[redacted]")
              : typeof data?.XErr === "number" ? ` (XErr ${data.XErr})` : "";
            reject(new Error(`${label} failed with HTTP ${status}${detail}`));
          } else if (!data || typeof data !== "object") reject(new Error(`${label} returned invalid JSON.`));
          else resolve(data);
        });
      });
      req.on("error", reject);
      req.setTimeout(timeout, () => req.destroy(new Error(`${label} timed out.`)));
      req.end(typeof body === "string" ? body : body === undefined ? undefined : JSON.stringify(body));
    });
  }

  try {
    const ms = await request("https://login.live.com/oauth20_token.srf", "Microsoft OAuth refresh", new URLSearchParams({
      client_id: DEFAULT_REFRESH_CLIENT_ID,
      redirect_uri: options.microsoftRedirectUri || "https://login.live.com/oauth20_desktop.srf",
      grant_type: "refresh_token", refresh_token: token,
      scope: options.microsoftScope || "service::user.auth.xboxlive.com::MBI_SSL",
    }).toString());
    if (!ms.access_token) throw new Error("Microsoft OAuth refresh returned no access token.");
    const xbl = await request("https://user.auth.xboxlive.com/user/authenticate", "Xbox Live authentication", {
      Properties: { AuthMethod: "RPS", SiteName: "user.auth.xboxlive.com", RpsTicket: /^[dt]=/.test(ms.access_token) ? ms.access_token : `t=${ms.access_token}` },
      RelyingParty: "http://auth.xboxlive.com", TokenType: "JWT",
    });
    const userHash = xbl.DisplayClaims?.xui?.[0]?.uhs;
    if (!xbl.Token || !userHash) throw new Error("Xbox Live response was missing token or user hash.");
    const xsts = await request("https://xsts.auth.xboxlive.com/xsts/authorize", "XSTS authorization", {
      Properties: { SandboxId: "RETAIL", UserTokens: [xbl.Token] },
      RelyingParty: "rp://api.minecraftservices.com/", TokenType: "JWT",
    });
    if (!xsts.Token) throw new Error("XSTS response was missing token.");
    const mc = await request("https://api.minecraftservices.com/authentication/login_with_xbox", "Minecraft login", {
      identityToken: `XBL3.0 x=${userHash};${xsts.Token}`,
    });
    if (!mc.access_token) throw new Error("Minecraft response was missing access token.");
    const jwt = parseJwtPayload<{ pfd?: Array<{ type?: string; name?: string; id?: string }>; profiles?: { mc?: string } }>(mc.access_token);
    const claim = jwt?.pfd?.find(item => item.type === "mc");
    let username = claim?.name;
    let uuid = claim?.id || jwt?.profiles?.mc;
    if (options.fetchProfile !== false) {
      const profile = await request("https://api.minecraftservices.com/minecraft/profile", "Minecraft profile lookup", undefined, { Authorization: `Bearer ${mc.access_token}` });
      if (!profile.name || !profile.id) throw new Error("Minecraft profile response was missing name or UUID.");
      username = profile.name;
      uuid = profile.id;
    }
    return { accessToken: mc.access_token, refreshToken: ms.refresh_token || token, username, uuid, expiresIn: mc.expires_in ?? 86400, obtainedOn: Date.now() };
  } finally {
    agent?.destroy();
  }
}
