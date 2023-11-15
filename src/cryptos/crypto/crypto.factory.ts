import { Crypto } from './crypto';

export const CRYPTO = {
  AES_192_CBC: 'AES-192-CBC',
  AES_256_CBC: 'AES-256-CBC',
} as const;
export type CRYPTO = (typeof CRYPTO)[keyof typeof CRYPTO];

export const create = (crypto: CRYPTO, password: string | Buffer, salt: string | Buffer, iv?: Buffer) => {
  switch (crypto) {
    case CRYPTO.AES_192_CBC:
      return new Crypto('aes-192-cbc', password, salt, 192 / 8, iv);
    case CRYPTO.AES_256_CBC:
      return new Crypto('aes-256-cbc', password, salt, 256 / 8, iv);
  }
};
