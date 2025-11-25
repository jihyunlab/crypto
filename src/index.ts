import { HashCreator } from './hashes/hash.creator';
import { HASH, Hash } from './interfaces/hash.interface';
import { CipherCreator } from './ciphers/cipher.creator';
import { CIPHER, Cipher, CipherOptions } from './interfaces/cipher.interface';
import { CryptoCreator } from './cryptos/crypto.creator';
import { CRYPTO, Crypto, CryptoOptions } from './interfaces/crypto.interface';
import { HashedIdHelper } from './helpers/hashed-id.helper';
import { RandomNumberHelper } from './helpers/random-number.helper';
import { JwtHelper } from './helpers/jwt.helper';
import { PkceHelper } from './helpers/pkce.helper';

export const createHash = async (hash: HASH) => {
  return await HashCreator.create(hash);
};

export const createCipher = async (
  cipher: CIPHER,
  secret: string,
  options?: CipherOptions
) => {
  return await CipherCreator.create(cipher, secret, options);
};

export const createCrypto = async (crypto: CRYPTO, options?: CryptoOptions) => {
  return await CryptoCreator.create(crypto, options);
};

export {
  HASH,
  Hash,
  CIPHER,
  Cipher,
  CipherOptions,
  CRYPTO,
  Crypto,
  CryptoOptions,
  HashedIdHelper,
  RandomNumberHelper,
  JwtHelper,
  PkceHelper,
};
