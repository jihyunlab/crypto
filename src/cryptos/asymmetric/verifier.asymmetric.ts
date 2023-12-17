import * as crypto from 'crypto';

export class Verifier {
  private key: crypto.KeyObject;

  constructor(key: crypto.KeyObject) {
    this.key = key;
  }

  verify(message: Buffer, signature: Buffer) {
    return crypto.verify(null, message, this.key, signature);
  }
}
