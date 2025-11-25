import { CIPHER, Cipher, CipherOptions } from '../interfaces/cipher.interface';
import { NodeCipher } from './node.cipher';

export const CipherCreator = {
  async create(cipher: CIPHER, password: string, options?: CipherOptions) {
    let instance: Cipher;

    let ivLength: number | undefined;
    let tagLength: number | undefined;

    if (
      options &&
      options.ivLength !== undefined &&
      options.ivLength !== null
    ) {
      ivLength = options.ivLength;
    }

    if (
      options &&
      options.tagLength !== undefined &&
      options.tagLength !== null
    ) {
      tagLength = options.tagLength / 8;
    }

    switch (cipher) {
      case CIPHER.AES_256_CBC:
        instance = await NodeCipher.create(
          'aes-256-cbc',
          256,
          password,
          ivLength || 16,
          undefined,
          undefined,
          options
        );
        break;
      case CIPHER.AES_256_GCM:
        instance = await NodeCipher.create(
          'aes-256-gcm',
          256,
          password,
          ivLength || 12,
          tagLength,
          options?.additionalData,
          options
        );
        break;
      default:
        throw new Error(`${cipher} does not exist.`);
    }

    return instance;
  },
};
