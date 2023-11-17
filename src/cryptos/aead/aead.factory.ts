import { Aead } from './aead';

export const AEAD = {
  AES_128_CCM: 'AES-128-CCM',
  AES_192_CCM: 'AES-192-CCM',
  AES_256_CCM: 'AES-256-CCM',
  AES_128_GCM: 'AES-128-GCM',
  AES_192_GCM: 'AES-192-GCM',
  AES_256_GCM: 'AES-256-GCM',
} as const;
export type AEAD = (typeof AEAD)[keyof typeof AEAD];

export const create = (aead: AEAD, key: string | Buffer, authTagLength?: number, aad?: Buffer) => {
  switch (aead) {
    case AEAD.AES_128_CCM:
      return new Aead('aes-128-ccm', key, authTagLength, aad);
    case AEAD.AES_192_CCM:
      return new Aead('aes-192-ccm', key, authTagLength, aad);
    case AEAD.AES_256_CCM:
      return new Aead('aes-256-ccm', key, authTagLength, aad);
    case AEAD.AES_128_GCM:
      return new Aead('aes-128-gcm', key, authTagLength, aad);
    case AEAD.AES_192_GCM:
      return new Aead('aes-192-gcm', key, authTagLength, aad);
    case AEAD.AES_256_GCM:
      return new Aead('aes-256-gcm', key, authTagLength, aad);
  }
};
