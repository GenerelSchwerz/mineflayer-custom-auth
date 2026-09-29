# Bot examples

Run these from the project root after `npm install` and `npm run build`.
Node.js 22.12 or newer is required. The server defaults to `localhost:25565`;
replace the optional host and port with your Minecraft Java server.

## Refresh token

Set only `REFRESH_TOKEN=your_token` in `.env`, then run:

```powershell
node --env-file=.env examples/refresh-token.js localhost 25565
```

To use an external or custom `.env` file without copying it:

```bash
node --env-file=/path/to/.env examples/refresh-token.js localhost 25565
```

The project default OAuth client is used. `MICROSOFT_CLIENT_ID` is an optional
override for tokens issued to a different client. The example never prints the
input token. The actual Minecraft username comes from the authenticated profile.

## Cookie file

```powershell
node examples/cookies.js ./cookies.txt localhost 25565
```

JSON cookie exports also work. The example uses browserless authentication first
and falls back to the browser, matching `authMethod: 'auto'`.

## Minecraft access token

Set `MINECRAFT_ACCESS_TOKEN=your_minecraft_access_token` in `.env`, then run:

```powershell
node --env-file=.env examples/access-token.js localhost 25565
```

All examples return the bot from `main()` for reuse and report connection errors
through the bot's `error` event. No example makes a connection merely by being imported.
