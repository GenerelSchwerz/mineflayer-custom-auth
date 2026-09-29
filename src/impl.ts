import path from "path";
import crypto from "crypto";
import { CookieCacheManager, createCookieAuthenticator } from "./cookies/cookieManager";
import { buildJavaPatchedManager, buildLivePatchedManager, DEFAULT_REFRESH_CLIENT_ID } from "./tokenAccess";
import { BotOptions, createBot as oldCreateBot } from "mineflayer";
import type { Client, ClientOptions } from "minecraft-protocol";
import { CookieOptions } from ".";
import { LiveCacheEntry, MinecraftJavaCacheEntry } from "./types";
import { getAccessToken } from "./unified";

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
  };
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
  options.authTitle ??= Titles.MinecraftNintendoSwitch;
  extendedOptions.deviceType ??= "Nintendo";
  extendedOptions.flow ??= "live";
}

/**
 * Handle authentication using cached tokens or Microsoft auth
 */
async function authenticateWithCache(client: Client, clientOptions: ClientOptions, cookieOptions: CookieOptions) {
  // Initialize authenticator
  validateOptions(clientOptions);

  const cookieInput = cookieOptions?.cookies ?? cookieOptions?.cookieFile;
  if (!cookieOptions || !cookieInput) {
    throw new Error("Missing cookie options for authentication. Provide 'cookies' or 'cookieFile'.");
  }

  const cachePath = clientOptions.profilesFolder as unknown as string;
  const auth = createCookieAuthenticator(
    cookieOptions.authMethod ?? "auto",
    cachePath,
    cookieOptions.headless,
    cookieOptions.executablePath,
    "mca",
    {
      allowUnsafeProxyTls: cookieOptions.allowUnsafeProxyTls,
      timeout: cookieOptions.timeout,
      fetchProfile: cookieOptions.fetchProfile,
      microsoftClientId: cookieOptions.microsoftClientId,
      microsoftRedirectUri: cookieOptions.microsoftRedirectUri,
      microsoftScope: cookieOptions.microsoftScope,
    }
  );
  const proxy = cookieOptions.proxy;

  const authResult = await auth.processAccount(clientOptions.username, cookieInput, proxy);
  if (!authResult.success) {
    throw new Error(authResult.error ?? "Cookie authentication failed before Minecraft protocol authentication.");
  }

  debug(`Pre-authentication ${authResult.fromCache ? "from cache" : "successful"}`);
  if (!authResult.token) throw new Error("Cookie authentication returned no Minecraft token.");
  clientOptions.javaAccessToken = authResult.token;
  await authenticateWithAccessToken(client, clientOptions);
}

const maybeClearCookieCache = async (client: Client, clientOptions: ClientOptions) => {
  validateOptions(clientOptions);
  const cachePath = clientOptions.profilesFolder as unknown as string;
  const auth = new CookieCacheManager(cachePath);

  try {
    const res = await auth.getCachedAccessToken(clientOptions.username);
    if (res != null) {
      if (res.is_cookie) {
        debug("Clearing cookie cache for Microsoft auth");
        await auth.clearCache(clientOptions.username);
      }
    } else {
      debug("No cached token found for Microsoft auth, continue as normal.");
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
    if (wasAccessTokenFlow) {
      console.warn('Try "refreshToken" as your auth method in bot options instead.');
    }
  }
}

function customTokenAuthFlow(client: Client, clientOptions: ClientOptions) {
  const authClient = client as AuthClient;
  const extendedOptions = clientOptions as ExtendedClientOptions;

  validateOptions(clientOptions);

  if (!authClient.authflow) {
    const credential = clientOptions.javaAccessToken || clientOptions.liveRefreshToken || clientOptions.liveAccessToken;
    const cacheIdentity = credential
      ? "custom_" + crypto.createHash("sha256").update(JSON.stringify([credential, clientOptions.authTitle, extendedOptions.flow])).digest("hex")
      : clientOptions.username;
    authClient.authflow = new Authflow(cacheIdentity, clientOptions.profilesFolder, extendedOptions, clientOptions.onMsaCode);
  }

  const authflow = authClient.authflow!;

  if (clientOptions.javaAccessToken) {
    authflow.mca = buildJavaPatchedManager(authflow.mca, clientOptions.javaAccessToken!);
  }

  if (!clientOptions.liveAccessToken && !clientOptions.liveRefreshToken) return;

  if (extendedOptions.flow === "live" || extendedOptions.flow === "sisu") {
    authflow.msa = buildLivePatchedManager(authflow.msa, {
      accessToken: clientOptions.liveAccessToken,
      refreshToken: clientOptions.liveRefreshToken,
    });
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
  if (clientOptions.liveRefreshToken) {
    const extended = clientOptions as ExtendedClientOptions;
    if (extended.flow && extended.flow !== "live" && extended.flow !== "sisu") throw new Error("Refresh tokens require a live or sisu flow.");
    const result = await getAccessToken({ refreshToken: clientOptions.liveRefreshToken }, {
      profilesFolder: typeof clientOptions.profilesFolder === "string" ? clientOptions.profilesFolder : undefined,
      authTitle: clientOptions.authTitle,
      microsoftClientId: clientOptions.authTitle,
      flow: extended.flow as "live" | "sisu" | undefined,
      deviceType: extended.deviceType,
      fetchProfile: false,
    });
    clientOptions.javaAccessToken = result.accessToken;
    clientOptions.liveRefreshToken = result.refreshToken ?? clientOptions.liveRefreshToken;
    clientOptions.authTitle ??= extended.flow === "sisu" ? Titles.MinecraftNintendoSwitch : DEFAULT_REFRESH_CLIENT_ID;
    await authenticateWithAccessToken(client, clientOptions);
    return;
  }
  customTokenAuthFlow(client, clientOptions);
  await microsoftAuth.authenticate(client, clientOptions);
}

function forwardAuthErrors(authenticate: (client: Client, options: ClientOptions) => Promise<void>) {
  return (client: Client, options: ClientOptions) => {
    // minecraft-protocol does not await custom auth callbacks.
    void Promise.resolve().then(() => authenticate(client, options)).catch(error => client.emit("error", error));
  };
}

export function createBot(botOptions: BotOptions) {
  botOptions = { ...botOptions, ...(botOptions.cookieOptions ? { cookieOptions: { ...botOptions.cookieOptions } } : {}) };
  // Normalize root options
  if (botOptions.cookieFile) {
    botOptions.cookieOptions = {
      ...botOptions.cookieOptions,
      cookieFile: botOptions.cookieFile,
    };
  }

  const anyBotOptions = botOptions as any;
  if (botOptions.refreshToken && !anyBotOptions.liveRefreshToken) {
    anyBotOptions.liveRefreshToken = botOptions.refreshToken;
  }
  if (botOptions.accessToken && !anyBotOptions.javaAccessToken) {
    anyBotOptions.javaAccessToken = botOptions.accessToken;
  }

  // Auto-detect auth mode if not explicitly specified
  if (!botOptions.auth || botOptions.auth === ("auto" as any)) {
    if (botOptions.cookieOptions?.cookieFile || botOptions.cookieOptions?.cookies) {
      botOptions.auth = "cookies";
    } else if (anyBotOptions.liveRefreshToken || anyBotOptions.liveAccessToken) {
      botOptions.auth = "refreshToken";
    } else if (anyBotOptions.javaAccessToken) {
      botOptions.auth = "accessToken";
    }
  }

  switch (botOptions.auth) {
    case "cookies": {
      botOptions.auth = forwardAuthErrors(async (client: Client, clientOptions: ClientOptions) => {
        const cookieInput = botOptions.cookieOptions?.cookies ?? botOptions.cookieOptions?.cookieFile;
        if (!botOptions.cookieOptions || !cookieInput) {
          throw new Error("Missing cookies or cookieFile for authentication in bot options.");
        }
        await authenticateWithCache(client, clientOptions, botOptions.cookieOptions);
      });
      break;
    }

    case "accessToken": {
      botOptions.auth = forwardAuthErrors(authenticateWithAccessToken);
      break;
    }

    case "refreshToken": {
      botOptions.auth = forwardAuthErrors(authenticateWithRefreshToken);
      break;
    }

    case "microsoft": {
      botOptions.auth = forwardAuthErrors(maybeClearCookieCache);
      break;
    }
  }

  return oldCreateBot(botOptions);
}
