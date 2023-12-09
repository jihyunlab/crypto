import { Hash } from './crypto.hash';

export const HASH = {
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
export type HASH = (typeof HASH)[keyof typeof HASH];

export const create = (hash: string) => {
  return new Hash(hash);
};
