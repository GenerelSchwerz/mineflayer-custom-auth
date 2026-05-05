import path from "path";
import { MinecraftAuthenticator } from "./cookies/cookieManager";
import { buildJavaPatchedManager, buildLivePatchedManager } from "./tokenAccess";
import { BotOptions, createBot as oldCreateBot } from "mineflayer";
import type { Client, ClientOptions } from "minecraft-protocol";
import { CookieOptions } from ".";
import { LiveCacheEntry, MinecraftJavaCacheEntry } from "./types";

// Constants
const { Authflow, Titles } = require("prismarine-auth");
const minecraftFolderPath = require("minecraft-folder-path");
const microsoftAuth = require("minecraft-protocol/src/client/microsoftAuth");
const debug = require("debug")("mineflayer-custom-auth");

type AuthflowLike<T extends unknown> = {
  mca: {
    cache: {
      getCached: () => Promise<T>;
    };
  };
  msa: {
    cache: {
      getCached: () => Promise<T>;
    };
  }
};

type AuthClient = Client & {
  authflow?: AuthflowLike<MinecraftJavaCacheEntry & LiveCacheEntry>;
};

type ExtendedClientOptions = ClientOptions & {
  deviceType?: string;
  flow?: string;
  haveCredentials?: boolean;
};

function validateOptions(options: ClientOptions) {
  const extendedOptions = options as ExtendedClientOptions;

  if (!options.profilesFolder) {
    options.profilesFolder = path.join(minecraftFolderPath, "nmp-cache");
  }
  if (options.authTitle === undefined) {
    options.authTitle = Titles.MinecraftNintendoSwitch;
    extendedOptions.deviceType = "Nintendo";
    extendedOptions.flow = "live";
  }
}

/**
 * Handle authentication using cached tokens or Microsoft auth
 */
async function authenticateWithCache(client: Client, clientOptions: ClientOptions, cookieOptions: CookieOptions) {
  // Initialize authenticator
  validateOptions(clientOptions);

  if (!cookieOptions || !cookieOptions.cookies) {
    throw new Error("Missing cookie options for authentication.");
  }

  // technically, this will always be a string. potential typing error on pris-auth's end?
  const cachePath = clientOptions.profilesFolder as unknown as string; // validated above.
  const auth = new MinecraftAuthenticator(cachePath, cookieOptions.headless, cookieOptions.executablePath);
  const proxy = cookieOptions.proxy;


  try {
    // Try to pre-authenticate and prepare cache
    const authResult = await auth.processAccount(clientOptions.username, cookieOptions.cookies, proxy);

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

const maybeClearCookieCache = async (client: Client, clientOptions: ClientOptions) => {
  validateOptions(clientOptions);
  const cachePath = clientOptions.profilesFolder as unknown as string; // validated above.
  const auth = new MinecraftAuthenticator(cachePath);

  try {
    const res = await auth.getCachedAccessToken(clientOptions.username);
    if (res != null) {
      if (res.is_cookie) {
        debug("Clearing cookie cache for Microsoft auth");
        auth.clearCache(clientOptions.username);
      }
    } else {
      debug("No cached token found for Microsoft auth, continue as normal.")
    }
  } catch (err) {
    debug("Failed to clear cookie cache:", err);
  } finally {
    // Always use minecraft-protocol's built-in auth as fallback
    await microsoftAuth.authenticate(client, clientOptions);
  }
};


function accessTokenWarningGate(client: Client, clientOptions: ClientOptions) {
  if (!clientOptions.javaAccessToken) {
    console.warn("No javaAccessToken provided in client options. Access token authentication may fail.");
    refreshTokenWarningGate(client, clientOptions, true);
  }
}

function refreshTokenWarningGate(client: Client, clientOptions: ClientOptions, wasAccessTokenFlow = false) {
  if (!clientOptions.liveAccessToken && !clientOptions.liveRefreshToken) {
    throw new Error("No access tokens provided in client options. Access token authentication cannot proceed.");
  } else {
    console.warn("liveAccessToken or liveRefreshToken is provided, so live authentication may still work.");
    if (wasAccessTokenFlow) {
      console.warn("Try \"refreshToken\" as your auth method in bot options instead.");
    }
  }
}

function customTokenAuthFlow(client: Client, clientOptions: ClientOptions) {
  const authClient = client as AuthClient;
  const extendedOptions = clientOptions as ExtendedClientOptions;

  validateOptions(clientOptions);

  if (!authClient.authflow) {
    authClient.authflow = new Authflow(clientOptions.username, clientOptions.profilesFolder, extendedOptions, clientOptions.onMsaCode);
  }

  const authflow = authClient.authflow!;
  
  if (clientOptions.javaAccessToken) {
    authflow.mca = buildJavaPatchedManager(
      authflow.mca,
      clientOptions.javaAccessToken!
    );
  }

  // skip next loader if not needed.
  
  if (!clientOptions.liveAccessToken && !clientOptions.liveRefreshToken) return;

  if (extendedOptions.flow === 'live' || extendedOptions.flow === 'sisu') {
    authflow.msa = buildLivePatchedManager(
      authflow.msa,
      {
        accessToken: clientOptions.liveAccessToken,
        refreshToken: clientOptions.liveRefreshToken,
      }
    );
  } else {
    throw new Error(`Unsupported auth flow "${extendedOptions.flow}". Only "live" and "sisu" flows are supported for live token patching.`);
  }
}

async function authenticateWithAccessToken(client: Client, clientOptions: ClientOptions) {
  accessTokenWarningGate(client, clientOptions);
  customTokenAuthFlow(client, clientOptions);
  await microsoftAuth.authenticate(client, clientOptions);
}

async function authenticateWithRefreshToken(client: Client, clientOptions: ClientOptions) {
  refreshTokenWarningGate(client, clientOptions);
  customTokenAuthFlow(client, clientOptions);
  await microsoftAuth.authenticate(client, clientOptions);
}

export function createBot(botOptions: BotOptions) {
  switch (botOptions.auth) {
    case "cookies": {
      botOptions.auth = async (client: Client, clientOptions: ClientOptions) => {
        if (!botOptions.cookieOptions || !botOptions.cookieOptions.cookies) {
          throw new Error("Missing cookie path for authentication in bot options.");
        }
        await authenticateWithCache(client, clientOptions, botOptions.cookieOptions);
      };
      break;
    }

    case "accessToken": {
      botOptions.auth = authenticateWithAccessToken;
      break;
    }

    case "refreshToken": {
      botOptions.auth = authenticateWithRefreshToken;
      break;
    }

    case "microsoft": {
      botOptions.auth = maybeClearCookieCache;
      break;
    }
  }

  return oldCreateBot(botOptions);
}
