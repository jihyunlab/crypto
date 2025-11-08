import { HASH, Hash } from './interfaces/hash.interface';
import { CIPHER, Cipher, CipherOptions } from './interfaces/cipher.interface';
import { HashCreator } from './hashes/hash.creator';
import { CipherCreator } from './ciphers/cipher.creator';

export const createHash = async (hash: HASH) => {
  return await HashCreator.create(hash);
};

export const createCipher = async (
  cipher: CIPHER,
  secret: string,
  options?: CipherOptions
) => {
  return await CipherCreator.create(cipher, secret, options);
};

export { HASH, Hash, CIPHER, Cipher, CipherOptions };
