const assert = require("assert");
const fs = require("fs");
const path = require("path");
const {
  cookie,
  getAccessTokenFromBrowser,
  authenticateWithBrowserCookies,
  BrowserCookieAuthenticator,
  createCookieAuthenticator,
  createBot,
} = require("../dist");

console.log("Starting tests for CookieConverter updates...\n");

// 1. Verify exports
assert.strictEqual(typeof getAccessTokenFromBrowser, "function", "getAccessTokenFromBrowser should be a function");
assert.strictEqual(typeof authenticateWithBrowserCookies, "function", "authenticateWithBrowserCookies should be a function");
assert.strictEqual(typeof BrowserCookieAuthenticator, "function", "BrowserCookieAuthenticator should be a class");
assert.strictEqual(typeof createCookieAuthenticator, "function", "createCookieAuthenticator should be a function");
assert.strictEqual(typeof createBot, "function", "createBot should be a function");
assert.strictEqual(typeof cookie.loadCookies, "function", "cookie.loadCookies should be a function");
assert.strictEqual(typeof cookie.parseCookies, "function", "cookie.parseCookies should be a function");
console.log("✓ All exported functions and classes are present.");

// 2. Test Netscape / TSV cookie parsing
const netscapeData = [
  "# Netscape HTTP Cookie File",
  "#HttpOnly_.login.live.com\tTRUE\t/\tTRUE\t1750000000\tMSPAuth\tsecret_msp_value",
  ".live.com\tTRUE\t/\tFALSE\t1750000000\tPPLState\t1",
].join("\n");

const netscapeParsed = cookie.parseCookies(netscapeData);
assert.strictEqual(netscapeParsed.length, 2, "Should parse 2 cookies from Netscape data");
assert.strictEqual(netscapeParsed[0].name, "MSPAuth");
assert.strictEqual(netscapeParsed[0].value, "secret_msp_value");
assert.strictEqual(netscapeParsed[0].httpOnly, true, "Should detect #HttpOnly_ prefix");
assert.strictEqual(netscapeParsed[1].name, "PPLState");
assert.strictEqual(netscapeParsed[1].value, "1");
console.log("✓ Netscape format cookies parsed successfully (including #HttpOnly_).");

// 3. Test JSON cookie parsing (from browser extensions like EditThisCookie / Cookie-Editor)
const jsonData = JSON.stringify([
  {
    name: "MSPAuth",
    value: "json_msp_value",
    domain: ".login.live.com",
    path: "/",
    expirationDate: 1750000000,
    httpOnly: true,
    secure: true,
    sameSite: "no_restriction",
  },
  {
    name: "bearer_token",
    value: "eyDummyTokenValue",
    domain: ".minecraft.net",
    path: "/",
  },
]);

const jsonParsed = cookie.parseCookies(jsonData);
assert.strictEqual(jsonParsed.length, 2, "Should parse 2 cookies from JSON");
assert.strictEqual(jsonParsed[0].name, "MSPAuth");
assert.strictEqual(jsonParsed[0].value, "json_msp_value");
assert.strictEqual(jsonParsed[0].sameSite, "None");
assert.strictEqual(jsonParsed[1].name, "bearer_token");
assert.strictEqual(jsonParsed[1].value, "eyDummyTokenValue");
console.log("✓ JSON format cookies parsed successfully.");

// 4. Test loading from cookie file directly
const tempCookieFile = path.join(__dirname, "temp_test_cookies.txt");
fs.writeFileSync(tempCookieFile, netscapeData, "utf8");

try {
  const loadedFromFile = cookie.loadCookies(tempCookieFile);
  assert.strictEqual(loadedFromFile.length, 2, "Should load 2 cookies directly from file path");
  assert.strictEqual(loadedFromFile[0].name, "MSPAuth");
  console.log("✓ Direct file path loading works seamlessly.");
} finally {
  if (fs.existsSync(tempCookieFile)) {
    fs.unlinkSync(tempCookieFile);
  }
}

// 5. Test loading from multiple files array
const tempFile1 = path.join(__dirname, "temp_file1.txt");
const tempFile2 = path.join(__dirname, "temp_file2.json");
fs.writeFileSync(tempFile1, ".live.com\tTRUE\t/\tTRUE\t1750000000\tCookieA\tValueA\n", "utf8");
fs.writeFileSync(tempFile2, JSON.stringify([{ name: "CookieB", value: "ValueB", domain: ".minecraft.net" }]), "utf8");

try {
  const loadedFromMultiple = cookie.loadCookies([tempFile1, tempFile2]);
  assert.strictEqual(loadedFromMultiple.length, 2, "Should load from multiple file paths");
  assert.strictEqual(loadedFromMultiple[0].name, "CookieA");
  assert.strictEqual(loadedFromMultiple[1].name, "CookieB");
  console.log("✓ Multiple cookie files loading works seamlessly.");
} finally {
  if (fs.existsSync(tempFile1)) fs.unlinkSync(tempFile1);
  if (fs.existsSync(tempFile2)) fs.unlinkSync(tempFile2);
}

// 6. Test browser authenticator initialization with options
const authenticator = createCookieAuthenticator("browser", path.join(__dirname, "cache"), true, "", "mca", {
  timeout: 30000,
});
assert.strictEqual(typeof authenticator.processAccount, "function");
assert.strictEqual(typeof authenticator.getToken, "function");
console.log("✓ Browser authenticator initialization with options passed.");

console.log("\nAll tests passed successfully!");
