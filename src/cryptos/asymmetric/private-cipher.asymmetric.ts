import * as crypto from 'crypto';

export class PrivateCipher {
  private key: crypto.RsaPrivateKey | crypto.KeyLike;

  constructor(key: crypto.RsaPrivateKey | crypto.KeyLike) {
    this.key = key;
  }

  encrypt(message: Buffer) {
    return crypto.privateEncrypt(this.key, message);
  }

  decrypt(message: Buffer) {
    return crypto.privateDecrypt(this.key, message);
  }
}
