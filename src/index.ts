import { create as createHash, HASH } from './cryptos/hash/hash.factory';
import { create as createHmac, HMAC } from './cryptos/hmac/hmac.factory';
import { create as createCrypto, CRYPTO } from './cryptos/crypto/crypto.factory';
import { create as createAead, AEAD } from './cryptos/aead/aead.factory';

export const Hash = {
  create: (hash: HASH) => {
    return createHash(hash);
  },
};

export const Hmac = {
  create: (hmac: HMAC, key: string | Buffer) => {
    return createHmac(hmac, key);
  },
};

export const Crypto = {
  create: (
    crypto: CRYPTO,
    password: string | Buffer,
    salt: string | Buffer,
    pbkdf2 = true,
    rounds = 1024,
    hash: HASH = HASH.SHA_512
  ) => {
    return createCrypto(crypto, password, salt, pbkdf2, rounds, hash);
  },
};

export const Aead = {
  create: (aead: AEAD, key: string | Buffer, authTagLength?: number, aad?: Buffer) => {
    return createAead(aead, key, authTagLength, aad);
  },
};

export { HASH, HMAC, CRYPTO, AEAD };
