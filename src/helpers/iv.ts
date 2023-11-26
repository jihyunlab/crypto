import * as crypto from 'crypto';
import { CIPHER } from '../cryptos/cipher/cipher.factory';
import { Cipher } from './cipher';

export const Iv = {
  normalize(algorithm: CIPHER, iv: string | Buffer) {
    const info = Cipher.info(algorithm);
    let normalized: string | Buffer | null;

    if (!info.ivLength) {
      return null;
    }

    normalized = iv;

    if (typeof iv === 'string') {
      if (info.ivLength !== Buffer.from(iv, 'utf8').length) {
        const buffer = Buffer.alloc(info.ivLength);
        normalized = Buffer.concat([Buffer.from(iv, 'utf8'), buffer]).subarray(0, info.ivLength);
        normalized = normalized.toString('utf8');
      }
    } else {
      if (info.ivLength !== iv.length) {
        const buffer = Buffer.alloc(info.ivLength);
        normalized = Buffer.concat([Buffer.from(iv), buffer]).subarray(0, info.ivLength);
      }
    }

    return normalized;
  },

  generate(algorithm: CIPHER) {
    const info = Cipher.info(algorithm);
    let generated: Buffer | null = null;

    if (info.ivLength !== undefined && info.ivLength > 0) {
      generated = Buffer.from(crypto.randomFillSync(new Uint8Array(info.ivLength)));
    }

    return generated;
  },
};
