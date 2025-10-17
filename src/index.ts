export { MinecraftAuthenticator } from "./cookies/cookieManager";

import {cookie} from './cookies/cookie'
import type { ClientOptions } from "minecraft-protocol";

import "mineflayer";
import { CookieOptions } from "./types";



declare module "mineflayer" {
  interface BotOptions {
    auth: ClientOptions["auth"] | "cookies";
    cookieOptions?: CookieOptions;
  }
}


export type { CookieOptions } from "./types";
export { createBot } from "./impl";
export { cookie } from './cookies/cookie';
