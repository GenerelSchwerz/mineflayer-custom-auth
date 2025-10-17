export { MinecraftAuthenticator } from "./cookies/cookieManager";

import {cookie} from './cookies/cookie'
import type { ClientOptions } from "minecraft-protocol";

import "mineflayer";


export interface CookieOptions {
  cookies?: cookie.Cookie[];
  headless?: boolean;
  executablePath?: string;
}

declare module "mineflayer" {
  interface BotOptions {
    auth: ClientOptions["auth"] | "cookies";
    cookieOptions?: CookieOptions;
  }
}



export { createBot } from "./impl";
export {cookie} from './cookies/cookie'
