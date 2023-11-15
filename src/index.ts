import { createHash, createHmac, HASH, HMAC } from './cryptos/hash';

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
