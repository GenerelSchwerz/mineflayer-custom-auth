'use strict';

const fs = require('fs');
const path = require('path');
const { cookieFileToJwt, clearCachedSession } = require('./working');

const args = process.argv.slice(2);
const fresh = args.includes('--fresh');
const fileArg = args.find(arg => arg !== '--fresh');
const cookiePath = path.resolve(fileArg || path.join(__dirname, 'data', 'gen.txt'));

async function main() {
  if (!fs.existsSync(cookiePath)) {
    throw new Error(`Cookie file not found: ${cookiePath}`);
  }

  if (fresh) {
    clearCachedSession(fs.readFileSync(cookiePath, 'utf8'));
  }

  const result = await cookieFileToJwt(cookiePath);

  console.log(JSON.stringify({
    success: true,
    cookieFile: cookiePath,
    cacheBypassed: fresh,
    username: result.username,
    uuid: result.uuid,
    accessTokenPresent: Boolean(result.accessToken),
    refreshedTokenPresent: Boolean(result.newRefreshToken),
  }, null, 2));
}

main().catch(error => {
  console.error(JSON.stringify({
    success: false,
    cookieFile: cookiePath,
    cacheBypassed: fresh,
    error: error instanceof Error ? error.message : String(error),
  }, null, 2));
  process.exitCode = 1;
});
