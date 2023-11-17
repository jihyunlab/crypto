import * as crypto from 'crypto';

export class Hmac {
  private hmac: crypto.Hmac;

  constructor(algorithm: string, key: string | Buffer) {
    this.hmac = crypto.createHmac(algorithm, key);
  }

  update(text: string | Buffer) {
    this.hmac.update(text);
    return this;
  }

  binary() {
    return this.hmac.digest('binary');
  }

  hex() {
    return this.hmac.digest('hex');
  }

  base64() {
    return this.hmac.digest('base64');
  }

  digest() {
    return this.hmac.digest();
  }

  buffer() {
    return this.digest();
  }

  uint8Array() {
    return new Uint8Array(this.digest());
  }
}
