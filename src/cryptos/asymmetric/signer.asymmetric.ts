import * as crypto from 'crypto';

export class Signer {
  private key: crypto.KeyObject;

  constructor(key: crypto.KeyObject) {
    this.key = key;
  }

  sign(message: Buffer) {
    return crypto.sign(null, message, this.key);
  }
}
