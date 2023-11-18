import * as crypto from 'crypto';
import { AEAD } from '../cryptos/aead/aead.factory';
import { Cipher } from './cipher';

export const Nonce = {
  normalize(algorithm: AEAD, nonce: string | Buffer) {
    const info = Cipher.info(algorithm);
    let normalized: string | Buffer | null;

    if (!info.ivLength) {
      throw new Error('nonce length information not found.');
    }

    normalized = nonce;

    if (typeof nonce === 'string') {
      if (info.ivLength !== Buffer.from(nonce, 'utf8').length) {
        const buffer = Buffer.alloc(info.ivLength);
        normalized = Buffer.concat([Buffer.from(nonce, 'utf8'), buffer]).subarray(0, info.ivLength);
        normalized = normalized.toString('utf8');
      }
    } else {
      if (info.ivLength !== nonce.length) {
        const buffer = Buffer.alloc(info.ivLength);
        normalized = Buffer.concat([Buffer.from(nonce), buffer]).subarray(0, info.ivLength);
      }
    }

    return normalized;
  },

  generate(algorithm: AEAD) {
    const info = Cipher.info(algorithm);
    let generated: Buffer | null = null;

    if (info.ivLength !== undefined && info.ivLength > 0) {
      generated = crypto.randomBytes(info.ivLength);
    } else {
      throw new Error('nonce cannot be generated automatically.');
    }

    return generated;
  },
};
