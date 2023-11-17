import * as crypto from 'crypto';

export class Hash {
  private hash: crypto.Hash;

  constructor(algorithm: string) {
    this.hash = crypto.createHash(algorithm);
  }

  update(text: string | Buffer) {
    this.hash.update(text);
    return this;
  }

  binary() {
    return this.hash.digest('binary');
  }

  hex() {
    return this.hash.digest('hex');
  }

  base64() {
    return this.hash.digest('base64');
  }

  digest() {
    return this.hash.digest();
  }

  buffer() {
    return this.digest();
  }

  uint8Array() {
    return new Uint8Array(this.digest());
  }
}
