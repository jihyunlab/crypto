import { Hmac } from './hmac';

export const HMAC = {
  MD5: 'md5',
  SHA1: 'sha1',
  SHA224: 'sha224',
  SHA256: 'sha256',
  SHA384: 'sha384',
  SHA512: 'sha512',
  SHA3_224: 'sha3-224',
  SHA3_256: 'sha3-256',
  SHA3_384: 'sha3-384',
  SHA3_512: 'sha3-512',
  SM3: 'sm3',
} as const;
export type HMAC = (typeof HMAC)[keyof typeof HMAC];

export const create = (hmac: string, key: string | Buffer) => {
  return new Hmac(hmac, key);
};
