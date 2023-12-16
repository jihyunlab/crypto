import * as crypto from 'crypto';
import { CIPHER } from '../cryptos/cipher/crypto-factory.cipher';
import { AEAD } from '../cryptos/aead/crypto-factory.aead';

export const Cipher = {
  info(algorithm: CIPHER | AEAD) {
    const info = crypto.getCipherInfo(algorithm);

    if (!info) {
      throw new Error('cipher information not found.');
    }

    return info;
  },

  hashes() {
    return crypto.getHashes();
  },

  ciphers() {
    return crypto.getCiphers();
  },

  curves() {
    return crypto.getCurves();
  },
};
