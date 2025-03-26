export { MinecraftAuthenticator } from "./cookieManager";

import type { ClientOptions } from "minecraft-protocol";

import "mineflayer";

declare module "mineflayer" {
  interface BotOptions {
    auth: ClientOptions["auth"] | "cookies";
    cookiePath?: string;
  }
}

export { createBot } from "./impl";
