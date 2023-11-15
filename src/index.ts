import { create as createHash, HASH } from './cryptos/hash/hash.factory';
import { create as createHmac, HMAC } from './cryptos/hmac/hmac.factory';

export const Hash = {
  create: (hash: HASH) => {
    return createHash(hash);
  },
};

export const Hmac = {
  create: (hmac: HMAC, key: Buffer) => {
    return createHmac(hmac, key);
  },
};

export { HASH, HMAC };
