import { CookieData } from "puppeteer";


export namespace cookie {
    export type Cookie = CookieData


  /**
   * Parse cookies from a Netscape format cookie file
   *
   * @param cookieContent - Content of the cookie file
   * @returns Array of cookie objects
   */
  export function parseCookies(cookieContent: string): Cookie[] {
    const cookies = cookieContent.split("\n");
    const cookieObjects: Cookie[] = [];

    for (const cookie of cookies) {
      if (cookie.trim() !== "") {
        const columns = cookie.split("\t");
        if (columns.length < 7) continue;

        const website = columns[0]?.trim() || "";
        const path = columns[2]?.trim() || "";
        const name = columns[5]?.trim() || "";
        const value = columns[6]?.trim() || "";
   

        if (website && name && value) {
          const cookieObject: Cookie = {
            name: name,
            value: value,
            domain: website,
            path: path,
            expires: Math.floor(Date.now() / 1000) + 3.154e7, // 1 year in the future
            httpOnly: false,
            secure: false,
            sameSite: "Lax",
          };

          cookieObjects.push(cookieObject);
        }
      }
    }

    return cookieObjects;
  }
}