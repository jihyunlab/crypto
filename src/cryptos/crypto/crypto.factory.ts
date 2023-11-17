import { Crypto } from './crypto';

export const CRYPTO = {
  AES_128_CBC: 'AES-128-CBC',
  AES_192_CBC: 'AES-192-CBC',
  AES_256_CBC: 'AES-256-CBC',
  AES_128_CFB: 'AES-128-CFB',
  AES_192_CFB: 'AES-192-CFB',
  AES_256_CFB: 'AES-256-CFB',
  AES_128_CFB1: 'AES-128-CFB1',
  AES_192_CFB1: 'AES-192-CFB1',
  AES_256_CFB1: 'AES-256-CFB1',
  AES_128_CFB8: 'AES-128-CFB8',
  AES_192_CFB8: 'AES-192-CFB8',
  AES_256_CFB8: 'AES-256-CFB8',
  AES_128_CTR: 'AES-128-CTR',
  AES_192_CTR: 'AES-192-CTR',
  AES_256_CTR: 'AES-256-CTR',
  AES_128_OFB: 'AES-128-OFB',
  AES_192_OFB: 'AES-192-OFB',
  AES_256_OFB: 'AES-256-OFB',
  AES_128_ECB: 'AES-128-ECB',
  AES_192_ECB: 'AES-192-ECB',
  AES_256_ECB: 'AES-256-ECB',
} as const;
export type CRYPTO = (typeof CRYPTO)[keyof typeof CRYPTO];

export const create = (crypto: CRYPTO, password: string | Buffer, salt: string | Buffer) => {
  switch (crypto) {
    case CRYPTO.AES_128_CBC:
      return new Crypto('aes-128-cbc', password, salt, 128 / 8);
    case CRYPTO.AES_192_CBC:
      return new Crypto('aes-192-cbc', password, salt, 192 / 8);
    case CRYPTO.AES_256_CBC:
      return new Crypto('aes-256-cbc', password, salt, 256 / 8);
    case CRYPTO.AES_128_CFB:
      return new Crypto('aes-128-cfb', password, salt, 128 / 8);
    case CRYPTO.AES_192_CFB:
      return new Crypto('aes-192-cfb', password, salt, 192 / 8);
    case CRYPTO.AES_256_CFB:
      return new Crypto('aes-256-cfb', password, salt, 256 / 8);
    case CRYPTO.AES_128_CFB1:
      return new Crypto('aes-128-cfb1', password, salt, 128 / 8);
    case CRYPTO.AES_192_CFB1:
      return new Crypto('aes-192-cfb1', password, salt, 192 / 8);
    case CRYPTO.AES_256_CFB1:
      return new Crypto('aes-256-cfb1', password, salt, 256 / 8);
    case CRYPTO.AES_128_CFB8:
      return new Crypto('aes-128-cfb8', password, salt, 128 / 8);
    case CRYPTO.AES_192_CFB8:
      return new Crypto('aes-192-cfb8', password, salt, 192 / 8);
    case CRYPTO.AES_256_CFB8:
      return new Crypto('aes-256-cfb8', password, salt, 256 / 8);
    case CRYPTO.AES_128_CTR:
      return new Crypto('aes-128-ctr', password, salt, 128 / 8);
    case CRYPTO.AES_192_CTR:
      return new Crypto('aes-192-ctr', password, salt, 192 / 8);
    case CRYPTO.AES_256_CTR:
      return new Crypto('aes-256-ctr', password, salt, 256 / 8);
    case CRYPTO.AES_128_OFB:
      return new Crypto('aes-128-ofb', password, salt, 128 / 8);
    case CRYPTO.AES_192_OFB:
      return new Crypto('aes-192-ofb', password, salt, 192 / 8);
    case CRYPTO.AES_256_OFB:
      return new Crypto('aes-256-ofb', password, salt, 256 / 8);
    case CRYPTO.AES_128_ECB:
      return new Crypto('aes-128-ecb', password, salt, 128 / 8);
    case CRYPTO.AES_192_ECB:
      return new Crypto('aes-192-ecb', password, salt, 192 / 8);
    case CRYPTO.AES_256_ECB:
      return new Crypto('aes-256-ecb', password, salt, 256 / 8);
  }
};
