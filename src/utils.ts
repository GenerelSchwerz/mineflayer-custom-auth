  import path from 'path'
  const { createHash } = require("prismarine-auth/src/common/Util");

  
  /**
   * Generate cache file name for a given username
   */
  export function generateCacheFileName(pathName: string, cacheName: string, username: string): string {
    return  path.join(pathName,`${createHash(username)}_${cacheName}-cache.json`)
  }