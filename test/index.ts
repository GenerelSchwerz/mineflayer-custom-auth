import {createBot} from '../src'

const bot = createBot({
    username: 'Generel_Schwerz',
    host: 'anticheat-test.com',
    auth: 'microsoft',
    cookiePath: './cookies/Nyxoxh.txt',
    profilesFolder: __dirname
})

bot.on('spawn', () => {
    console.log(bot.username)
})