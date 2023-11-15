import { Hash } from './hash';

export const HASH = {
  SHA_224: 'SHA-224',
  SHA_256: 'SHA-256',
  SHA_384: 'SHA-384',
  SHA_512: 'SHA-512',
  SHA3_224: 'SHA3-224',
  SHA3_256: 'SHA3-256',
  SHA3_384: 'SHA3-384',
  SHA3_512: 'SHA3-512',
} as const;
export type HASH = (typeof HASH)[keyof typeof HASH];

export const create = (hash: HASH) => {
  switch (hash) {
    case HASH.SHA_224:
      return new Hash('sha224');
    case HASH.SHA_256:
      return new Hash('sha256');
    case HASH.SHA_384:
      return new Hash('sha384');
    case HASH.SHA_512:
      return new Hash('sha512');
    case HASH.SHA3_224:
      return new Hash('sha3-224');
    case HASH.SHA3_256:
      return new Hash('sha3-256');
    case HASH.SHA3_384:
      return new Hash('sha3-384');
    case HASH.SHA3_512:
      return new Hash('sha3-512');
  }
};
