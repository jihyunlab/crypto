import * as crypto from 'crypto';
import { HASH } from '../cryptos/hash/hash.factory';
import { CRYPTO } from '../cryptos/crypto/crypto.factory';
import { AEAD } from '../cryptos/aead/aead.factory';
import { Cipher } from './cipher';

export const PBKDF = {
  PBKDF: 'PBKDF',
  PBKDF2: 'PBKDF2',
} as const;
export type PBKDF = (typeof PBKDF)[keyof typeof PBKDF];

export const Key = {
  normalize(algorithm: CRYPTO | AEAD, key: string | Buffer) {
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
    algorithm: CRYPTO | AEAD,
    password: string | Buffer,
    salt: string | Buffer,
    pbkdf: PBKDF = PBKDF.PBKDF2,
    rounds = 1024,
    hash: HASH = HASH.SHA_512
  ) {
    const info = Cipher.info(algorithm);

    switch (pbkdf) {
      case PBKDF.PBKDF:
        return crypto.scryptSync(password, salt, info.keyLength);
      case PBKDF.PBKDF2:
        return crypto.pbkdf2Sync(password, salt, rounds, info.keyLength, hash);
    }
  },
};
