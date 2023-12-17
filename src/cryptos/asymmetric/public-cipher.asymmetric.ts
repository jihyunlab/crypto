import * as crypto from 'crypto';

export class PublicCipher {
  private key: crypto.RsaPublicKey | crypto.KeyLike;

  constructor(key: crypto.RsaPublicKey | crypto.KeyLike) {
    this.key = key;
  }

  encrypt(message: Buffer) {
    return crypto.publicEncrypt(this.key, message);
  }

  decrypt(message: Buffer) {
    return crypto.publicDecrypt(this.key, message);
  }
}
