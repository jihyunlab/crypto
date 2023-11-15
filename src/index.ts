import { create as createHash, HASH } from './cryptos/hash/hash.factory';
import { create as createHmac, HMAC } from './cryptos/hmac/hmac.factory';
import { create as createCrypto, CRYPTO } from './cryptos/crypto/crypto.factory';

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

export const Crypto = {
  create: (crypto: CRYPTO, password: string | Buffer, salt: string | Buffer, iv?: Buffer) => {
    return createCrypto(crypto, password, salt, iv);
  },
};

export { HASH, HMAC };
