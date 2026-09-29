'use strict';

const { createBot } = require('..');

function connect(authOptions, host = 'localhost', port = '25565') {
  const serverPort = Number(port);
  if (!Number.isInteger(serverPort) || serverPort < 1 || serverPort > 65535) {
    throw new Error('Server port must be an integer from 1 to 65535.');
  }
  const bot = createBot({ host, port: serverPort, username: 'my-account', ...authOptions });
  bot.on('spawn', () => console.log(`Connected as ${bot.username}`));
  bot.on('error', error => {
    console.error(`Bot error: ${error.message}`);
    process.exitCode = 1;
  });
  bot.on('kicked', reason => console.error('Disconnected by server:', reason));
  return bot;
}

function run(main) {
  try { main(); } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

module.exports = { connect, run };
