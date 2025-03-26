import path from "path";
import { MinecraftAuthenticator } from "../src";

// Constants
const minecraftFolderPath = require("minecraft-folder-path");
const microsoftAuth = require("minecraft-protocol/src/client/microsoftAuth");

import type { Client, ClientOptions } from "minecraft-protocol";

import { BotOptions, createBot as oldCreateBot } from "mineflayer";

const debug = require("debug")("mineflayer-custom-auth")

/**
 * Handle authentication using cached tokens or Microsoft auth
 */
async function authenticateWithCache(
  client: Client,
  clientOptions: ClientOptions,
  username: string,
  cookiePath: string,
  profilesFolder?: string | false
) {
  // Initialize authenticator

  let auth;
  if (profilesFolder === false) {
    const cachePath = path.join(minecraftFolderPath, "nmp-cache");
    auth = new MinecraftAuthenticator(cachePath, true);
  } else {
    const cachePath = profilesFolder ?? path.join(minecraftFolderPath, "nmp-cache");
    auth = new MinecraftAuthenticator(cachePath, true);
  }

  try {
    // Try to pre-authenticate and prepare cache
    const authResult = await auth.processAccount(username, cookiePath);

    if (authResult.success) {
      debug(`Pre-authentication ${authResult.fromCache ? "from cache" : "successful"}`);
    }
  } catch (err) {
    debug("Pre-authentication failed:", err);
  } finally {
    // Always use minecraft-protocol's built-in auth as fallback
    await microsoftAuth.authenticate(client, clientOptions);
  }
}

export function createBot(botOptions: BotOptions) {
  if (botOptions.auth === "cookies") {
    botOptions.auth = async (client: Client, clientOptions: ClientOptions) => {
      if (!botOptions.cookiePath) {
        throw new Error("Missing cookie path for authentication in bot options.");
      }
      await authenticateWithCache(client, clientOptions, botOptions.username, botOptions.cookiePath, botOptions.profilesFolder);
    };
  }

  return oldCreateBot(botOptions);
}
