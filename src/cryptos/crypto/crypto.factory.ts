import { Crypto } from './crypto';

export const CRYPTO = {
  AES_128_CBC: 'aes-128-cbc',
  AES_192_CBC: 'aes-192-cbc',
  AES_256_CBC: 'aes-256-cbc',
  AES_128_CFB: 'aes-128-cfb',
  AES_192_CFB: 'aes-192-cfb',
  AES_256_CFB: 'aes-256-cfb',
  AES_128_CFB1: 'aes-128-cfb1',
  AES_192_CFB1: 'aes-192-cfb1',
  AES_256_CFB1: 'aes-256-cfb1',
  AES_128_CFB8: 'aes-128-cfb8',
  AES_192_CFB8: 'aes-192-cfb8',
  AES_256_CFB8: 'aes-256-cfb8',
  AES_128_CTR: 'aes-128-ctr',
  AES_192_CTR: 'aes-192-ctr',
  AES_256_CTR: 'aes-256-ctr',
  AES_128_OFB: 'aes-128-ofb',
  AES_192_OFB: 'aes-192-ofb',
  AES_256_OFB: 'aes-256-ofb',
  AES_128_ECB: 'aes-128-ecb',
  AES_192_ECB: 'aes-192-ecb',
  AES_256_ECB: 'aes-256-ecb',
} as const;
export type CRYPTO = (typeof CRYPTO)[keyof typeof CRYPTO];

export const create = (crypto: string, key: string | Buffer) => {
  return new Crypto(crypto, key);
};
