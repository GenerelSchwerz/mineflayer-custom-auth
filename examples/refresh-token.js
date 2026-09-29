'use strict';

const { connect, run } = require('./common');

function main(env = process.env, args = process.argv.slice(2)) {
  if (!env.REFRESH_TOKEN?.trim()) throw new Error('Set REFRESH_TOKEN in .env, then run node --env-file=.env examples/refresh-token.js [host] [port].');
  return connect({
    auth: 'refreshToken',
    refreshToken: env.REFRESH_TOKEN,
    ...(env.MICROSOFT_CLIENT_ID ? { authTitle: env.MICROSOFT_CLIENT_ID } : {}),
  }, args[0], args[1]);
}

if (require.main === module) run(main);
module.exports = { main };
