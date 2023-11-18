import { Aead } from './aead';

export const AEAD = {
  AES_128_CCM: 'aes-128-ccm',
  AES_192_CCM: 'aes-192-ccm',
  AES_256_CCM: 'aes-256-ccm',
  AES_128_GCM: 'aes-128-gcm',
  AES_192_GCM: 'aes-192-gcm',
  AES_256_GCM: 'aes-256-gcm',
} as const;
export type AEAD = (typeof AEAD)[keyof typeof AEAD];

export const create = (aead: AEAD, key: string | Buffer, authTagLength?: number, aad?: Buffer) => {
  return new Aead(aead, key, authTagLength, aad);
};
