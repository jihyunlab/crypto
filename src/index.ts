import { create as createHash, HASH } from './cryptos/hash/crypto-factory.hash';
import { create as createHmac, HMAC } from './cryptos/hmac/crypto-factory.hmac';
import { create as createCipher, CIPHER } from './cryptos/cipher/crypto-factory.cipher';
import { create as createAead, AEAD } from './cryptos/aead/crypto-factory.aead';
import {
  createPrivateCipher,
  createPublicCipher,
  createSigner,
  createVerifier,
} from './cryptos/asymmetric/crypto-factory.asymmetric';
import { Cipher as CipherHelper } from './helpers/cipher.helper';
import { Key as KeyHelper, PBKDF } from './helpers/key.helper';
import { KeyPair as KeyPairHelper, CURVE } from './helpers/keypair.helper';
import { Iv as IvHelper } from './helpers/iv.helper';
import { Nonce as NonceHelper } from './helpers/nonce.helper';
import * as crypto from 'crypto';

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

export const Cipher = {
  create: (cipher: string, key: string | Buffer) => {
    return createCipher(cipher, key);
  },
};

export const Aead = {
  create: (aead: AEAD, key: string | Buffer, authTagLength?: 4 | 6 | 8 | 10 | 12 | 14 | 16, aad?: Buffer) => {
    return createAead(aead, key, authTagLength, aad);
  },
};

export const Asymmetric = {
  create: {
    signer: (key: crypto.KeyObject) => {
      return createSigner(key);
    },
    verifier: (key: crypto.KeyObject) => {
      return createVerifier(key);
    },
    privateCipher: (key: crypto.RsaPrivateKey | crypto.KeyLike) => {
      return createPrivateCipher(key);
    },
    publicCipher: (key: crypto.RsaPublicKey | crypto.KeyLike) => {
      return createPublicCipher(key);
    },
  },
};

export const Helper = {
  cipher: CipherHelper,
  key: KeyHelper,
  keypair: KeyPairHelper,
  iv: IvHelper,
  nonce: NonceHelper,
};

export { HASH, HMAC, CIPHER, AEAD, PBKDF, CURVE };
