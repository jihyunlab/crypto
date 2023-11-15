import { ShaHash } from './hashes/sha/sha.hash';
import { ShaHmac } from './hashes/sha/sha.hmac';

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

export const HMAC = {
  SHA_224_HMAC: 'SHA-224-HMAC',
  SHA_256_HMAC: 'SHA-256-HMAC',
  SHA_384_HMAC: 'SHA-384-HMAC',
  SHA_512_HMAC: 'SHA-512-HMAC',
  SHA3_224_HMAC: 'SHA3-224-HMAC',
  SHA3_256_HMAC: 'SHA3-256-HMAC',
  SHA3_384_HMAC: 'SHA3-384-HMAC',
  SHA3_512_HMAC: 'SHA3-512-HMAC',
} as const;
export type HMAC = (typeof HMAC)[keyof typeof HMAC];

export const createHash = (hash: HASH) => {
  switch (hash) {
    case HASH.SHA_224:
      return new ShaHash('sha224');
    case HASH.SHA_256:
      return new ShaHash('sha256');
    case HASH.SHA_384:
      return new ShaHash('sha384');
    case HASH.SHA_512:
      return new ShaHash('sha512');
    case HASH.SHA3_224:
      return new ShaHash('sha3-224');
    case HASH.SHA3_256:
      return new ShaHash('sha3-256');
    case HASH.SHA3_384:
      return new ShaHash('sha3-384');
    case HASH.SHA3_512:
      return new ShaHash('sha3-512');
  }
};

export const createHmac = (hmac: HMAC, key: Buffer) => {
  switch (hmac) {
    case HMAC.SHA_224_HMAC:
      return new ShaHmac('sha224', key);
    case HMAC.SHA_256_HMAC:
      return new ShaHmac('sha256', key);
    case HMAC.SHA_384_HMAC:
      return new ShaHmac('sha384', key);
    case HMAC.SHA_512_HMAC:
      return new ShaHmac('sha512', key);
    case HMAC.SHA3_224_HMAC:
      return new ShaHmac('sha3-224', key);
    case HMAC.SHA3_256_HMAC:
      return new ShaHmac('sha3-256', key);
    case HMAC.SHA3_384_HMAC:
      return new ShaHmac('sha3-384', key);
    case HMAC.SHA3_512_HMAC:
      return new ShaHmac('sha3-512', key);
  }
};
