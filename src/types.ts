import { cookie } from "./cookies/cookie";

export interface CookieOptions {
  cookies?: cookie.Cookie[];
  headless?: boolean;
  executablePath?: string;
}
