import * as crypto from 'crypto';
import { HASH } from '../cryptos/hash/crypto-factory.hash';
import { Cipher } from './cipher.helper';

export const PBKDF = {
  PBKDF: 'PBKDF',
  PBKDF2: 'PBKDF2',
} as const;
export type PBKDF = (typeof PBKDF)[keyof typeof PBKDF];

export const Key = {
  normalize(algorithm: string /* CIPHER | AEAD */, key: string | Buffer) {
    const info = Cipher.info(algorithm);
    let normalized: string | Buffer;

    normalized = key;

    if (typeof key === 'string') {
      if (info.keyLength !== Buffer.from(key, 'utf8').length) {
        const buffer = Buffer.alloc(info.keyLength);
        normalized = Buffer.concat([Buffer.from(key, 'utf8'), buffer]).subarray(0, info.keyLength);
        normalized = normalized.toString('utf8');
      }
    } else {
      if (info.keyLength !== key.length) {
        const buffer = Buffer.alloc(info.keyLength);
        normalized = Buffer.concat([Buffer.from(key), buffer]).subarray(0, info.keyLength);
      }
    }

    return normalized;
  },

  generate(
    algorithm: string /* CIPHER | AEAD */,
    password: string | Buffer,
    salt: string | Buffer,
    pbkdf: PBKDF = PBKDF.PBKDF2,
    rounds = 1024,
    hash: string /* HASH */ = HASH.SHA512
  ) {
    const info = Cipher.info(algorithm);

    switch (pbkdf) {
      case PBKDF.PBKDF:
        return this.scrypt(password, salt, info.keyLength);
      case PBKDF.PBKDF2:
        return this.pbkdf2(password, salt, rounds, info.keyLength, hash);
    }
  },

  scrypt(
    password: crypto.BinaryLike,
    salt: crypto.BinaryLike,
    keylen: number,
    options?: crypto.ScryptOptions | undefined
  ) {
    return crypto.scryptSync(password, salt, keylen, options);
  },

  pbkdf2(password: crypto.BinaryLike, salt: crypto.BinaryLike, iterations: number, keylen: number, digest: string) {
    return crypto.pbkdf2Sync(password, salt, iterations, keylen, digest);
  },
};
