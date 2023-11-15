import * as crypto from 'crypto';

export class Crypto {
  private algorithm: string;
  private password: string | Buffer;
  private salt: string | Buffer;
  private keylen: number;
  private iv?: Buffer;

  constructor(algorithm: string, password: string | Buffer, salt: string | Buffer, keylen: number, iv?: Buffer) {
    this.algorithm = algorithm;
    this.password = password;
    this.salt = salt;
    this.keylen = keylen;

    if (iv) {
      this.iv = iv;
    } else {
      // TODO: Generate iv
    }
  }

  encrypt() {}

  decrypt() {}
}
