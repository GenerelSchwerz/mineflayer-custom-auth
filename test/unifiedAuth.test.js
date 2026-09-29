const assert = require("assert");
const fs = require("fs");
const path = require("path");
const {
  getAccessToken,
  getMinecraftToken,
  getAccessTokenFromBrowser,
  getAccessTokenFromRefreshToken,
  createBot,
} = require("../dist");

console.log("Running unified auth tests...\n");

// 1. Verify function exports
assert.strictEqual(typeof getAccessToken, "function", "getAccessToken should be a function");
assert.strictEqual(typeof getMinecraftToken, "function", "getMinecraftToken should be a function");
assert.strictEqual(typeof getAccessTokenFromBrowser, "function", "getAccessTokenFromBrowser should be a function");
assert.strictEqual(typeof getAccessTokenFromRefreshToken, "function", "getAccessTokenFromRefreshToken should be a function");
assert.strictEqual(typeof createBot, "function", "createBot should be a function");
console.log("✓ All unified auth functions are exported.");

// 2. Test auto-detection on cookie file vs refresh token
const dummyCookiePath = path.join(__dirname, "dummy_cookies.txt");
fs.writeFileSync(
  dummyCookiePath,
  ".live.com\tTRUE\t/\tTRUE\t1800000000\tPPLState\t1\nlogin.live.com\tFALSE\t/\tTRUE\t1800000000\t__Host-MSAAUTH\t11\n",
  "utf8"
);

(async () => {
  try {
    // 3. Test cookie file input detection (will attempt browser/browserless)
    let cookieFlowTriggered = false;
    try {
      await getAccessToken(dummyCookiePath, { timeout: 1000, headless: true });
    } catch (e) {
      // It should trigger cookie/browser flow, not refresh token flow
      cookieFlowTriggered = !e.message.includes("Live OAuth");
    }
    assert.strictEqual(cookieFlowTriggered, true, "Should route cookie file to browser/cookie flow");
    console.log("✓ Cookie file routing verified.");

    // 4. Test refresh token string routing
    let refreshFlowTriggered = false;
    try {
      await getAccessToken("M.R3_BL2_sample_refresh_token");
    } catch (e) {
      // It should trigger Live OAuth refresh exchange
      refreshFlowTriggered = e.message.includes("401") || e.message.includes("OAuth") || e.message.includes("Failed");
    }
    assert.strictEqual(refreshFlowTriggered, true, "Should route string token to refresh token flow");
    console.log("✓ Refresh token routing verified.");

    console.log("\nAll unified auth tests passed!");
  } finally {
    if (fs.existsSync(dummyCookiePath)) {
      fs.unlinkSync(dummyCookiePath);
    }
  }
})();
