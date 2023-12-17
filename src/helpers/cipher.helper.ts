import * as crypto from 'crypto';

export const Cipher = {
  info(algorithm: string /* CIPHER | AEAD */) {
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
