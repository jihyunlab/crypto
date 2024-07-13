import { Cipher } from './interfaces/cipher.interface';
import { CipherCreator } from './ciphers/cipher.creator';

export const createCipher = async (
  cipher: 'aes-256-cbc' | 'aes-256-gcm',
  secret: string,
  options?: {
    salt?: string;
    iterations?: number;
    ivLength?: number;
    tagLength?: 32 | 64 | 96 | 104 | 112 | 120 | 128;
    additionalData?: Uint8Array;
  }
) => {
  return await CipherCreator.create(cipher, secret, options);
};

export { Cipher };
