import { CIPHER, Cipher, CipherOptions } from './interfaces/cipher.interface';
import { CipherCreator } from './ciphers/cipher.creator';

export const createCipher = async (
  cipher: CIPHER,
  secret: string,
  options?: CipherOptions
) => {
  return await CipherCreator.create(cipher, secret, options);
};

export { CIPHER, Cipher, CipherOptions };
