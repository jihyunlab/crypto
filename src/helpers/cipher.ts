import * as crypto from 'crypto';
import { CIPHER } from '../cryptos/cipher/cipher.factory';
import { AEAD } from '../cryptos/aead/aead.factory';

export const Cipher = {
  info(algorithm: CIPHER | AEAD) {
    const info = crypto.getCipherInfo(algorithm);

    if (!info) {
      throw new Error('cipher information not found.');
    }

    return info;
  },
};
