import * as crypto from 'crypto';

export class Hash {
  private algorithm: string;
  private hash: crypto.Hash;

  constructor(algorithm: string) {
    this.algorithm = algorithm;
    this.hash = crypto.createHash(algorithm);
  }

  update(text: string | Buffer) {
    this.hash.update(text);
    return this;
  }

  binary() {
    return this.digest('binary').toString();
  }

  hex() {
    return this.digest('hex').toString();
  }

  base64() {
    return this.digest('base64').toString();
  }

  base64url() {
    return this.digest('base64url').toString();
  }

  digest(encoding?: crypto.BinaryToTextEncoding) {
    let result: string | Buffer;

    if (encoding) {
      result = this.hash.digest(encoding);
    } else {
      result = this.hash.digest();
    }

    this.hash = crypto.createHash(this.algorithm);
    return result;
  }

  buffer() {
    return Buffer.from(this.digest());
  }

  uint8Array() {
    return new Uint8Array(Buffer.from(this.digest()));
  }
}
