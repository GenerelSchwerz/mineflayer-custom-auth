# Cookie Login

## Cookie Format
<!-- link src/cookies/cookie.ts 's "parseCookies" -->
If you are using [parseCookies](../src/cookies/cookie.ts#L14) to parse cookies, the format should be as follows:
```bash
<website>	<something>	<path>	<secure>	<expiration>	<name>	<value>
```

### Example
```bash
.live.com   TRUE    /	FALSE	3784011825	MSPAuth	Disabled
```

I only use `website, path, name, value` in the code. The rest is auto-filled in. It still needs to be in the above format though.