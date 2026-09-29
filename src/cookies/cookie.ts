import fs from "fs";
import type { CookieData } from "puppeteer";

export namespace cookie {
  export type Cookie = CookieData;

  /**
   * Clean leading dots from a domain string
   */
  function cleanDomainString(domain?: string): string {
    let clean = (domain || "login.live.com").trim();
    while (clean.startsWith(".")) {
      clean = clean.substring(1);
    }
    return clean || "login.live.com";
  }

  /**
   * Normalize an individual cookie object
   */
  function normalizeCookie(c: Cookie): Cookie {
    const isHost = c.name?.startsWith("__Host-");
    const cleanDomain = cleanDomainString(c.domain);

    return {
      ...c,
      domain: isHost ? cleanDomain : `.${cleanDomain}`,
      path: isHost ? "/" : (c.path || "/"),
      expires: typeof c.expires === "number" && c.expires > 0 ? c.expires : Math.floor(Date.now() / 1000) + 31536000,
      httpOnly: Boolean(c.httpOnly),
      secure: isHost ? true : Boolean(c.secure),
      sameSite: (c.sameSite as "Strict" | "Lax" | "None") || "Lax",
    };
  }

  /**
   * Normalize JSON cookies from browser extension exports (Cookie-Editor, EditThisCookie, etc.)
   */
  function normalizeJsonCookie(raw: Record<string, unknown>): Cookie | null {
    if (!raw || typeof raw !== "object" || !raw.name || raw.value === undefined) return null;

    const rawExpires = typeof raw.expirationDate === "number"
      ? Math.floor(raw.expirationDate)
      : typeof raw.expires === "number"
      ? Math.floor(raw.expires)
      : Math.floor(Date.now() / 1000) + 31536000;

    let sameSite: "Strict" | "Lax" | "None" = "Lax";
    if (typeof raw.sameSite === "string") {
      const s = raw.sameSite.toLowerCase();
      if (s === "strict") sameSite = "Strict";
      else if (s === "none" || s === "no_restriction") sameSite = "None";
      else sameSite = "Lax";
    }

    const name = String(raw.name);
    const isHost = name.startsWith("__Host-");
    const cleanDomain = cleanDomainString(typeof raw.domain === "string" ? raw.domain : undefined);

    return {
      name,
      value: String(raw.value),
      domain: isHost ? cleanDomain : `.${cleanDomain}`,
      path: isHost ? "/" : (typeof raw.path === "string" ? raw.path : "/"),
      expires: rawExpires,
      httpOnly: Boolean(raw.httpOnly),
      secure: isHost ? true : Boolean(raw.secure),
      sameSite,
    };
  }

  /**
   * Load cookies from a file path, array of file paths, cookie string, or array of cookies
   *
   * @param input - File path, array of file paths, cookie content, or Cookie array
   * @returns Normalized array of cookies
   */
  export function loadCookies(input: string | string[] | Cookie[] | Buffer): Cookie[] {
    if (!input) return [];

    if (Array.isArray(input)) {
      if (input.length === 0) return [];
      if (typeof input[0] === "string") {
        return (input as string[]).flatMap((item) => loadCookies(item));
      }
      return (input as Cookie[]).map(normalizeCookie);
    }

    if (Buffer.isBuffer(input)) {
      return parseCookies(input.toString("utf8"));
    }

    if (typeof input === "string") {
      const trimmed = input.trim();
      // If it exists as a file on disk, read it
      if (fs.existsSync(trimmed)) {
        const content = fs.readFileSync(trimmed, "utf8");
        return parseCookies(content);
      }
      return parseCookies(trimmed);
    }

    return [];
  }

  /**
   * Parse cookies from a Netscape format file, JSON string, or semicolon header string
   *
   * @param cookieContent - Content of the cookie file or string
   * @returns Array of cookie objects
   */
  export function parseCookies(cookieContent: string): Cookie[] {
    if (!cookieContent) return [];

    const trimmed = cookieContent.trim();

    // 1. Try parsing JSON format (e.g. Cookie-Editor, EditThisCookie exports)
    if ((trimmed.startsWith("[") && trimmed.endsWith("]")) || (trimmed.startsWith("{") && trimmed.endsWith("}"))) {
      try {
        const parsed = JSON.parse(trimmed);
        const list = Array.isArray(parsed) ? parsed : [parsed];
        const cookies = list.map((item) => normalizeJsonCookie(item)).filter(Boolean) as Cookie[];
        if (cookies.length > 0) return cookies;
      } catch {
        // Fall back to line parsing
      }
    }

    // 2. Parse Netscape / TSV / Key-Value lines
    const lines = cookieContent.split(/\r?\n/);
    const cookieObjects: Cookie[] = [];

    for (const rawLine of lines) {
      let line = rawLine.trim();
      if (!line) continue;

      let isHttpOnly = false;
      if (line.startsWith("#HttpOnly_")) {
        isHttpOnly = true;
        line = line.substring(10).trim();
      } else if (line.startsWith("#") && !line.includes("\t")) {
        // Comment line
        continue;
      }

      // Check tab-separated columns (Netscape format)
      if (line.includes("\t")) {
        const columns = line.split("\t");
        if (columns.length >= 7) {
          const domain = columns[0]?.trim() || "";
          const cookiePath = columns[2]?.trim() || "/";
          const secure = columns[3]?.trim()?.toLowerCase() === "true";
          const rawExpiry = parseInt(columns[4]?.trim() || "0", 10);
          const name = columns[5]?.trim() || "";
          const value = columns[6]?.trim() || "";

          if (domain && name && value) {
            const isHost = name.startsWith("__Host-");
            const cleanDomain = cleanDomainString(domain);
            const expires = rawExpiry > 0 ? rawExpiry : Math.floor(Date.now() / 1000) + 31536000;
            cookieObjects.push({
              name,
              value,
              domain: isHost ? cleanDomain : `.${cleanDomain}`,
              path: isHost ? "/" : cookiePath,
              expires,
              httpOnly: isHttpOnly,
              secure: isHost ? true : secure,
              sameSite: "Lax",
            });
            continue;
          }
        }
      }

      // Check key=value format (e.g. Header or line-by-line cookies)
      if (line.includes("=") && !line.startsWith("#")) {
        const pairs = line.split(";");
        for (const pair of pairs) {
          const eqIdx = pair.indexOf("=");
          if (eqIdx <= 0) continue;
          const name = pair.substring(0, eqIdx).trim();
          const value = pair.substring(eqIdx + 1).trim();
          const lowerName = name.toLowerCase();
          if (
            name &&
            value &&
            lowerName !== "domain" &&
            lowerName !== "path" &&
            lowerName !== "expires" &&
            lowerName !== "samesite" &&
            lowerName !== "httponly" &&
            lowerName !== "secure"
          ) {
            const isHost = name.startsWith("__Host-");
            cookieObjects.push({
              name,
              value,
              domain: isHost ? "login.live.com" : ".live.com",
              path: "/",
              expires: Math.floor(Date.now() / 1000) + 31536000,
              httpOnly: isHttpOnly,
              secure: true,
              sameSite: "Lax",
            });
          }
        }
      }
    }

    return cookieObjects;
  }
}