export { MinecraftAuthenticator } from "./cookies/cookieManager";

import {cookie} from './cookies/cookie'
import type { ClientOptions } from "minecraft-protocol";

import "mineflayer";

declare module "mineflayer" {
  interface BotOptions {
    auth: ClientOptions["auth"] | "cookies";
    cookies?: cookie.Cookie[];
  }
}



export { createBot } from "./impl";
export {cookie} from './cookies/cookie'
