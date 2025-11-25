import {
  KeyLike,
  KeyObject,
  SignKeyObjectInput,
  SignPrivateKeyInput,
} from 'crypto';

export const CRYPTO = {
  RSA_SHA384: 'RSA-SHA384',
} as const;
export type CRYPTO = (typeof CRYPTO)[keyof typeof CRYPTO];

export type ExtendedJsonWebKey = JsonWebKey & {
  kid: string;
};

export interface Crypto {
  generateKeyPair: () => Promise<{ privateKey: string; publicKey: string }>;
  createPrivateKeyFromPem: (pem: string) => Promise<KeyObject>;
  createPublicKeyFromPem: (pem: string) => Promise<KeyObject>;
  createJwk: (kid: string, key: KeyObject) => Promise<ExtendedJsonWebKey>;
  createPublicKeyFromJwk: (jwk: ExtendedJsonWebKey) => Promise<KeyObject>;
  sign: (
    privateKey: KeyLike | SignKeyObjectInput | SignPrivateKeyInput,
    toBeSigned: Uint8Array
  ) => Promise<Uint8Array>;
  verify: (
    publicKey: KeyLike | SignKeyObjectInput,
    toBeSigned: Uint8Array,
    signature: Uint8Array
  ) => Promise<boolean>;
}

export interface CryptoOptions {
  modulusLength?: 2048 | 3072 | 4096;
  use?: 'sig' | 'enc';
}
