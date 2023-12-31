import * as crypto from 'crypto';

export class Hmac {
  private algorithm: string;
  private key: string | Buffer;
  private hmac: crypto.Hmac;

  constructor(algorithm: string, key: string | Buffer) {
    this.algorithm = algorithm;
    this.key = key;
    this.hmac = crypto.createHmac(algorithm, key);
  }

  update(text: string | Buffer) {
    this.hmac.update(text);
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
      result = this.hmac.digest(encoding);
    } else {
      result = this.hmac.digest();
    }

    this.hmac = crypto.createHmac(this.algorithm, this.key);
    return result;
  }

  buffer() {
    return Buffer.from(this.digest());
  }

  uint8Array() {
    return new Uint8Array(Buffer.from(this.digest()));
  }
}
