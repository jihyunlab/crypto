import { Hash } from './hash';

export const HASH = {
  SHA_224: 'sha224',
  SHA_256: 'sha256',
  SHA_384: 'sha384',
  SHA_512: 'sha512',
  SHA3_224: 'sha3-224',
  SHA3_256: 'sha3-256',
  SHA3_384: 'sha3-384',
  SHA3_512: 'sha3-512',
} as const;
export type HASH = (typeof HASH)[keyof typeof HASH];

export const create = (hash: string) => {
  return new Hash(hash);
};
