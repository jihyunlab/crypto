import { Hmac } from './hmac';

export const HMAC = {
  SHA_224: 'SHA-224',
  SHA_256: 'SHA-256',
  SHA_384: 'SHA-384',
  SHA_512: 'SHA-512',
  SHA3_224: 'SHA3-224',
  SHA3_256: 'SHA3-256',
  SHA3_384: 'SHA3-384',
  SHA3_512: 'SHA3-512',
} as const;
export type HMAC = (typeof HMAC)[keyof typeof HMAC];

export const create = (hmac: HMAC, key: string | Buffer) => {
  switch (hmac) {
    case HMAC.SHA_224:
      return new Hmac('sha224', key);
    case HMAC.SHA_256:
      return new Hmac('sha256', key);
    case HMAC.SHA_384:
      return new Hmac('sha384', key);
    case HMAC.SHA_512:
      return new Hmac('sha512', key);
    case HMAC.SHA3_224:
      return new Hmac('sha3-224', key);
    case HMAC.SHA3_256:
      return new Hmac('sha3-256', key);
    case HMAC.SHA3_384:
      return new Hmac('sha3-384', key);
    case HMAC.SHA3_512:
      return new Hmac('sha3-512', key);
  }
};
