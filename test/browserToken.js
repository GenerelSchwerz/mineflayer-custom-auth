const path = require("path");
const { getAccessTokenFromBrowser } = require("../dist");

/**
 * Example demonstrating launching a new browser, loading cookie files,
 * and extracting the Minecraft Java access token.
 */
async function main() {
  const input = process.argv[2] || path.join(__dirname, "data", "gen.txt");

  console.log("Launching browser and loading cookies from:", input);

  try {
    const result = await getAccessTokenFromBrowser(input, {
      headless: false, // set to true for headless background execution
      timeout: 45000,
      fetchProfile: true, // retrieves player username and UUID
    });

    console.log("\nAuthentication Succeeded!");
    console.log("Access Token:", result.accessToken.slice(0, 30) + "...");
    console.log("Player Username:", result.username);
    console.log("Player UUID:", result.uuid);
    console.log("Token Lifetime (s):", result.expiresIn);
  } catch (err) {
    console.error("\nError during browser authentication:", err.message);
  }
}

if (require.main === module) {
  main();
}
