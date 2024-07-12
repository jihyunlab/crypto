import {
  CIPHER,
  Cipher as NodeCipher,
  Options as CipherOptions,
} from './interfaces/cipher.interface';
import { CipherCreator } from './ciphers/cipher.creator';

export const Cipher = {
  create: async (cipher: CIPHER, secret: string, options?: CipherOptions) => {
    return await CipherCreator.create(cipher, secret, options);
  },
};

export { CIPHER, NodeCipher, CipherOptions };
