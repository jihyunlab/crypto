import * as crypto from 'crypto';
import { CRYPTO } from '../cryptos/crypto/crypto.factory';
import { AEAD } from '../cryptos/aead/aead.factory';

export const Cipher = {
  info(algorithm: CRYPTO | AEAD) {
    const info = crypto.getCipherInfo(algorithm);

    if (!info) {
      throw new Error('cipher information not found.');
    }

    return info;
  },
};
