const fs = require("fs");
const readline = require("readline/promises");
const { getAccessTokenFromRefreshToken, getAccessToken } = require("../dist");

async function main() {
  const args = process.argv.slice(2);
  let input;
  const options = { fetchProfile: true };
  let timeout = 60000;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--client-id") options.authTitle = args[++i];
    else if (args[i] === "--device-type") options.deviceType = args[++i];
    else if (args[i] === "--timeout") timeout = Number(args[++i]);
    else if (!input && !args[i].startsWith("--")) input = args[i];
    else throw new Error("Usage: node test/testRefreshToken.js [file] [--client-id ID] [--device-type TYPE] [--timeout MS]");
    if (args[i] === undefined) throw new Error("Missing option value.");
  }
  if (!Number.isFinite(timeout) || timeout <= 0 || timeout > 2147483647) {
    throw new Error("Timeout must be a positive number of milliseconds, at most 2147483647.");
  }
  if (!input) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    try {
      input = await rl.question("Paste your refresh token (or path to token/cookie file): ");
    } finally {
      rl.close();
    }
  }
  input = input.trim().replace(/^"(.*)"$/, "$1");
  if (!input) throw new Error("No input received.");

  let token = input;
  let cookieFile;
  if (fs.existsSync(input)) {
    token = fs.readFileSync(input, "utf8").trim();
    if (token.startsWith("[") || token.split(/\r?\n/).some(line => line.split("\t").length >= 7) || /(?:MSPAuth|__Host-MSAAUTH|PPLState)=/.test(token)) {
      cookieFile = input;
    }
  }
  if (!token) throw new Error("Input file is empty.");
  // A referenced timer keeps pending promises alive and guarantees a visible outcome.
  const deadline = setTimeout(() => {
    console.error(`Authentication timed out after ${timeout} ms.`);
    process.exit(1);
  }, timeout);
  try {
    let result;
    if (cookieFile) {
      console.log("Detected a cookie file; starting cookie authentication...");
      result = await getAccessToken({ cookieFile }, { ...options, timeout });
    } else if (token.startsWith("ey") && token.split(".").length === 3) {
      console.log("Reading JWT metadata (this does not verify the token with Microsoft).");
      result = await getAccessToken(token);
    } else {
      console.log(`Exchanging refresh token with client ${options.authTitle || "00000000402b5328 (default)"}...`);
      console.log("Use --client-id for the client that originally issued the refresh token.");
      result = await getAccessTokenFromRefreshToken(token, options);
    }
    console.log("Completed.");
    console.log("Player Username:", result.username || "N/A");
    console.log("Player UUID:", result.uuid || "N/A");
    console.log("Expires In (s):", result.expiresIn);
    console.log("Access token omitted from console output.");
  } catch (error) {
    throw new Error(String(error.message || error).split(token).join("[redacted]"));
  } finally {
    clearTimeout(deadline);
  }
}

if (require.main === module) {
  main().catch(error => {
    console.error("Authentication failed:", error.message);
    process.exitCode = 1;
  });
}

module.exports = { main };
