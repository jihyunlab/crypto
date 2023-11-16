import * as crypto from 'crypto';

export class Crypto {
  private algorithm: string;
  private password: string | Buffer;
  private salt: string | Buffer;
  private keylen: number;
  private iv: string | Buffer | null;

  constructor(
    algorithm: string,
    password: string | Buffer,
    salt: string | Buffer,
    keylen: number,
    iv?: string | Buffer | null
  ) {
    this.algorithm = algorithm;
    this.password = password;
    this.salt = salt;
    this.keylen = keylen;

    if (iv) {
      this.iv = iv;
    } else if (iv === null) {
      this.iv = null;
    } else {
      this.iv = null;
      const info = crypto.getCipherInfo(this.algorithm);

      if (info && info.ivLength !== undefined && info.ivLength > 0) {
        this.iv = Buffer.from(crypto.randomFillSync(new Uint8Array(info.ivLength)));
      }
    }
  }

  encrypt = {
    binary(
      text: string,
      inputEncoding?: 'base64' | 'base64url' | 'hex' | 'binary' | 'utf8' | 'utf-8' | 'utf16le' | 'utf-16le' | 'latin1'
    ) {
      if (!inputEncoding) {
        inputEncoding = 'utf-8';
      }

      return this.string(text, inputEncoding, 'binary');
    },
    hex(
      text: string,
      inputEncoding?: 'base64' | 'base64url' | 'hex' | 'binary' | 'utf8' | 'utf-8' | 'utf16le' | 'utf-16le' | 'latin1'
    ) {
      if (!inputEncoding) {
        inputEncoding = 'utf-8';
      }

      return this.string(text, inputEncoding, 'hex');
    },
    base64(
      text: string,
      inputEncoding?: 'base64' | 'base64url' | 'hex' | 'binary' | 'utf8' | 'utf-8' | 'utf16le' | 'utf-16le' | 'latin1'
    ) {
      if (!inputEncoding) {
        inputEncoding = 'utf-8';
      }

      return this.string(text, inputEncoding, 'base64');
    },
    uint8Array(text: Buffer) {
      const buffer = this.buffer(text);
      return { text: new Uint8Array(buffer.text), iv: buffer.iv };
    },
    string: (
      text: string,
      inputEncoding?: 'base64' | 'base64url' | 'hex' | 'binary' | 'utf8' | 'utf-8' | 'utf16le' | 'utf-16le' | 'latin1',
      outputEncoding?: 'base64' | 'base64url' | 'hex' | 'binary' | 'utf8' | 'utf-8' | 'utf16le' | 'utf-16le' | 'latin1'
    ) => {
      const key = crypto.scryptSync(this.password, this.salt, this.keylen);
      const info = crypto.getCipherInfo(this.algorithm);

      let iv = this.iv;

      if (iv && info) {
        if (info.ivLength === undefined) {
          iv = null;
        } else if (info.ivLength > 0 && iv.length !== info.ivLength) {
          if (typeof iv === 'string') {
            iv = iv + '0'.repeat(info.ivLength);
            iv = iv.slice(0, info.ivLength);
          } else {
            const buffer = Buffer.alloc(info.ivLength);
            iv = Buffer.concat([Buffer.from(iv), buffer]).subarray(0, info.ivLength);
          }
        }
      }

      const cipher = crypto.createCipheriv(this.algorithm, key, iv);

      if (!inputEncoding) {
        inputEncoding = 'utf-8';
      }

      if (!outputEncoding) {
        outputEncoding = 'hex';
      }

      let encrypted = cipher.update(text, inputEncoding, outputEncoding);
      encrypted = encrypted + cipher.final(outputEncoding);

      return { text: encrypted, iv: this.iv };
    },
    buffer: (text: Buffer) => {
      const key = crypto.scryptSync(this.password, this.salt, this.keylen);
      const info = crypto.getCipherInfo(this.algorithm);

      let iv = this.iv;

      if (iv && info) {
        if (info.ivLength === undefined) {
          iv = null;
        } else if (info.ivLength > 0 && iv.length !== info.ivLength) {
          if (typeof iv === 'string') {
            iv = iv + '0'.repeat(info.ivLength);
            iv = iv.slice(0, info.ivLength);
          } else {
            const buffer = Buffer.alloc(info.ivLength);
            iv = Buffer.concat([Buffer.from(iv), buffer]).subarray(0, info.ivLength);
          }
        }
      }

      const cipher = crypto.createCipheriv(this.algorithm, key, iv);

      let encrypted = cipher.update(text);
      encrypted = Buffer.concat([encrypted, cipher.final()]);

      return { text: encrypted, iv: this.iv };
    },
  };

  decrypt = {
    binary(
      text: string,
      outputEncoding?: 'base64' | 'base64url' | 'hex' | 'binary' | 'utf8' | 'utf-8' | 'utf16le' | 'utf-16le' | 'latin1'
    ) {
      return this.string(text, 'binary', outputEncoding);
    },
    hex(
      text: string,
      outputEncoding?: 'base64' | 'base64url' | 'hex' | 'binary' | 'utf8' | 'utf-8' | 'utf16le' | 'utf-16le' | 'latin1'
    ) {
      return this.string(text, 'hex', outputEncoding);
    },
    base64(
      text: string,
      outputEncoding?: 'base64' | 'base64url' | 'hex' | 'binary' | 'utf8' | 'utf-8' | 'utf16le' | 'utf-16le' | 'latin1'
    ) {
      return this.string(text, 'base64', outputEncoding);
    },
    uint8Array(text: Buffer) {
      const buffer = this.buffer(text);
      return new Uint8Array(buffer);
    },
    string: (
      text: string,
      inputEncoding?: 'base64' | 'base64url' | 'hex' | 'binary' | 'utf8' | 'utf-8' | 'utf16le' | 'utf-16le' | 'latin1',
      outputEncoding?: 'base64' | 'base64url' | 'hex' | 'binary' | 'utf8' | 'utf-8' | 'utf16le' | 'utf-16le' | 'latin1'
    ) => {
      const key = crypto.scryptSync(this.password, this.salt, this.keylen);
      const info = crypto.getCipherInfo(this.algorithm);

      let iv = this.iv;

      if (iv && info) {
        if (info.ivLength === undefined) {
          iv = null;
        } else if (info.ivLength > 0 && iv.length !== info.ivLength) {
          if (typeof iv === 'string') {
            iv = iv + '0'.repeat(info.ivLength);
            iv = iv.slice(0, info.ivLength);
          } else {
            const buffer = Buffer.alloc(info.ivLength);
            iv = Buffer.concat([Buffer.from(iv), buffer]).subarray(0, info.ivLength);
          }
        }
      }

      const decipher = crypto.createDecipheriv(this.algorithm, key, iv);

      if (!inputEncoding) {
        inputEncoding = 'hex';
      }

      if (!outputEncoding) {
        outputEncoding = 'utf-8';
      }

      let decrypted = decipher.update(text, inputEncoding, outputEncoding);
      decrypted = decrypted + decipher.final(outputEncoding);

      return decrypted;
    },
    buffer: (text: Buffer) => {
      const key = crypto.scryptSync(this.password, this.salt, this.keylen);
      const info = crypto.getCipherInfo(this.algorithm);

      let iv = this.iv;

      if (iv && info) {
        if (info.ivLength === undefined) {
          iv = null;
        } else if (info.ivLength > 0 && iv.length !== info.ivLength) {
          if (typeof iv === 'string') {
            iv = iv + '0'.repeat(info.ivLength);
            iv = iv.slice(0, info.ivLength);
          } else {
            const buffer = Buffer.alloc(info.ivLength);
            iv = Buffer.concat([Buffer.from(iv), buffer]).subarray(0, info.ivLength);
          }
        }
      }

      const decipher = crypto.createDecipheriv(this.algorithm, key, iv);

      let decrypted = decipher.update(text);
      decrypted = Buffer.concat([decrypted, decipher.final()]);

      return decrypted;
    },
  };
}
