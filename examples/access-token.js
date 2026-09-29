'use strict';

const { connect, run } = require('./common');

function main(env = process.env, args = process.argv.slice(2)) {
  if (!env.MINECRAFT_ACCESS_TOKEN?.trim()) throw new Error('Set MINECRAFT_ACCESS_TOKEN in .env, then run node --env-file=.env examples/access-token.js [host] [port].');
  return connect({ auth: 'accessToken', javaAccessToken: env.MINECRAFT_ACCESS_TOKEN }, args[0], args[1]);
}

if (require.main === module) run(main);
module.exports = { main };
