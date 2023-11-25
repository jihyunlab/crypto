import { create as createHash, HASH } from './cryptos/hash/hash.factory';
import { create as createHmac, HMAC } from './cryptos/hmac/hmac.factory';
import { create as createCrypto, CRYPTO } from './cryptos/crypto/crypto.factory';
import { create as createAead, AEAD, AuthTagLength } from './cryptos/aead/aead.factory';
import { Cipher } from './helpers/cipher';
import { Key, PBKDF } from './helpers/key';
import { Iv } from './helpers/iv';
import { Nonce } from './helpers/nonce';

export const Hash = {
  create: (hash: string) => {
    return createHash(hash);
  },
};

export const Hmac = {
  create: (hmac: string, key: string | Buffer) => {
    return createHmac(hmac, key);
  },
};

export const Crypto = {
  create: (crypto: string, key: string | Buffer) => {
    return createCrypto(crypto, key);
  },
};

export const Aead = {
  create: (aead: AEAD, key: string | Buffer, authTagLength?: AuthTagLength, aad?: Buffer) => {
    return createAead(aead, key, authTagLength, aad);
  },
};

export { HASH, HMAC, CRYPTO, AEAD, PBKDF, Cipher, Key, Iv, Nonce, AuthTagLength };
