import { create as createHash, HASH } from './cryptos/hash/crypto-factory.hash';
import { create as createHmac, HMAC } from './cryptos/hmac/crypto-factory.hmac';
import { create as createCipher, CIPHER } from './cryptos/cipher/crypto-factory.cipher';
import { create as createAead, AEAD } from './cryptos/aead/crypto-factory.aead';
import { Cipher as CipherHelper } from './helpers/cipher.helper';
import { Key as KeyHelper, PBKDF } from './helpers/key.helper';
import { KeyPair as KeyPairHelper, CURVE } from './helpers/keypair.helper';
import { Iv as IvHelper } from './helpers/iv.helper';
import { Nonce as NonceHelper } from './helpers/nonce.helper';
import * as crypto from 'crypto';

export const Hash = {
  create: (hash: string) => {
    return createHash(hash);
  },
};

export const Hmac = {
  create: (hmac: string, key: string | Buffer) => {
    return createHmac(hmac, key);
  },
};

export const Cipher = {
  create: (cipher: string, key: string | Buffer) => {
    return createCipher(cipher, key);
  },
};

export const Aead = {
  create: (aead: AEAD, key: string | Buffer, authTagLength?: 4 | 6 | 8 | 10 | 12 | 14 | 16, aad?: Buffer) => {
    return createAead(aead, key, authTagLength, aad);
  },
};

export const Asymmetric = {
  sign: (key: crypto.KeyObject, message: Buffer) => {
    return crypto.sign(null, message, key);
  },

  verify: (key: crypto.KeyObject, message: Buffer, signature: Buffer) => {
    return crypto.verify(null, message, key, signature);
  },

  privateEncrypt: (key: crypto.RsaPrivateKey | crypto.KeyLike, buffer: Buffer) => {
    return crypto.privateEncrypt(key, buffer);
  },
  privateDecrypt: (key: crypto.RsaPrivateKey | crypto.KeyLike, buffer: Buffer) => {
    return crypto.privateDecrypt(key, buffer);
  },
  publicEncrypt: (key: crypto.RsaPrivateKey | crypto.KeyLike, buffer: Buffer) => {
    return crypto.publicEncrypt(key, buffer);
  },
  publicDecrypt: (key: crypto.RsaPrivateKey | crypto.KeyLike, buffer: Buffer) => {
    return crypto.publicDecrypt(key, buffer);
  },
};

export const Helper = {
  cipher: CipherHelper,
  key: KeyHelper,
  keypair: KeyPairHelper,
  iv: IvHelper,
  nonce: NonceHelper,
};

export { HASH, HMAC, CIPHER, AEAD, PBKDF, CURVE };

// const keypair = Helper.keypair.generate.rsa({
//   modulusLength: 4096,
//   publicKeyEncoding: {
//     type: 'spki',
//     format: 'pem',
//   },
//   privateKeyEncoding: {
//     type: 'pkcs8',
//     format: 'pem',
//     cipher: 'aes-256-cbc',
//     passphrase: process.env.JIHYUNLAB_SECRET_KEY,
//   },
// });

// const buffer = Asymmetric.privateEncrypt(
//   { key: keypair.privateKey, passphrase: process.env.JIHYUNLAB_SECRET_KEY },
//   Buffer.from('jihyunlab')
// );
// const string = Asymmetric.publicDecrypt(keypair.publicKey, buffer).toString();
// console.log(string);

// const ecKeypair = Helper.keypair.generate.brainpoolP256();

// const signature = Asymmetric.sign(ecKeypair.privateKey, Buffer.from('jihyunlab'));
// console.log(signature.toString('hex'));

// const verify = Asymmetric.verify(ecKeypair.publicKey, Buffer.from('jihyunlab'), signature);
// console.log(verify);
