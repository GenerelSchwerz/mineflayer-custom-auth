# Mineflayer Custom Auth


## Why do it in a separate package?
Because these methods of logging in may be more involved. For example, this cookie login uses Puppeteer, which definitely won't be merged.

## Installation
```bash
# npm
npm install mineflayer-custom-auth

# yarn
yarn add mineflayer-custom-auth
```


## Usage
```js
import {createBot, cookie} from 'mineflayer-custom-auth'
import fs from 'fs'

// cookie namespace has everything you need to parse cookies.
const {parseCookies} = cookie

// read file contents into a string
const cookiePath = '<file name>';
const fileData = fs.readFileSync(cookiePath, 'utf-8')

// provided utility method to parse cookies.
const cookies = parseCookies(fileData)


const bot = createBot({
    username: 'Generel_Schwerz',
    auth: 'cookies',
    cookies: cookies, // required if using cookies auth
})
```
