'use strict';

const fs = require('node:fs');
const { connect, run } = require('./common');

function main(args = process.argv.slice(2)) {
  const [cookieFile, host, port] = args;
  if (!cookieFile || !fs.existsSync(cookieFile) || !fs.statSync(cookieFile).isFile()) {
    throw new Error('Usage: node examples/cookies.js <cookie-file> [host] [port]. The cookie file must exist.');
  }
  return connect({ auth: 'cookies', cookieOptions: { cookieFile, authMethod: 'auto' } }, host, port);
}

if (require.main === module) run(main);
module.exports = { main };
