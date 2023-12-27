import { Aead } from './crypto.aead';

export const AEAD = {
  AES_128_CCM: 'aes-128-ccm',
  AES_192_CCM: 'aes-192-ccm',
  AES_256_CCM: 'aes-256-ccm',
  AES_128_GCM: 'aes-128-gcm',
  AES_192_GCM: 'aes-192-gcm',
  AES_256_GCM: 'aes-256-gcm',
  AES_128_OCB: 'aes-128-ocb',
  AES_192_OCB: 'aes-192-ocb',
  AES_256_OCB: 'aes-256-ocb',
} as const;
export type AEAD = (typeof AEAD)[keyof typeof AEAD];

export const create = (
  aead: AEAD,
  key: string | Buffer,
  authTagLength: 4 | 6 | 8 | 10 | 12 | 14 | 16 | null = 16,
  aad?: Buffer
) => {
  if (!authTagLength) {
    return new Aead(aead, key, undefined, aad);
  } else {
    return new Aead(aead, key, authTagLength, aad);
  }
};
