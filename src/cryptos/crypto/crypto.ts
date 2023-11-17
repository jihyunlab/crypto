import * as crypto from 'crypto';

export class Crypto {
  private algorithm: string;
  private password: string | Buffer;
  private salt: string | Buffer;
  private keylen: number;

  constructor(algorithm: string, password: string | Buffer, salt: string | Buffer, keylen: number) {
    this.algorithm = algorithm;
    this.password = password;
    this.salt = salt;
    this.keylen = keylen;
  }

  iv(iv?: string | Buffer) {
    const info = crypto.getCipherInfo(this.algorithm);
    let generated: string | Buffer | null;

    if (!iv) {
      generated = null;

      if (info && info.ivLength !== undefined && info.ivLength > 0) {
        generated = Buffer.from(crypto.randomFillSync(new Uint8Array(info.ivLength)));
      }

      return generated;
    }

    generated = iv;

    if (info) {
      if (!info.ivLength) {
        generated = null;
      } else {
        if (typeof iv === 'string') {
          if (info.ivLength !== Buffer.from(iv, 'utf8').length) {
            const buffer = Buffer.alloc(info.ivLength);
            generated = Buffer.concat([Buffer.from(iv, 'utf8'), buffer]).subarray(0, info.ivLength);
            generated = generated.toString('utf8');
          }
        } else {
          if (info.ivLength !== iv.length) {
            const buffer = Buffer.alloc(info.ivLength);
            generated = Buffer.concat([Buffer.from(iv), buffer]).subarray(0, info.ivLength);
          }
        }
      }
    }

    return generated;
  }

  encrypt = {
    binary(text: string, iv: string | Buffer | null, inputEncoding?: crypto.Encoding) {
      if (!inputEncoding) {
        inputEncoding = 'utf8';
      }

      return this.string(text, iv, inputEncoding, 'binary');
    },
    hex(text: string, iv: string | Buffer | null, inputEncoding?: crypto.Encoding) {
      if (!inputEncoding) {
        inputEncoding = 'utf8';
      }

      return this.string(text, iv, inputEncoding, 'hex');
    },
    base64(text: string, iv: string | Buffer | null, inputEncoding?: crypto.Encoding) {
      if (!inputEncoding) {
        inputEncoding = 'utf8';
      }

      return this.string(text, iv, inputEncoding, 'base64');
    },
    uint8Array(text: Buffer, iv: string | Buffer | null) {
      const buffer = this.buffer(text, iv);
      return new Uint8Array(buffer);
    },
    string: (
      text: string,
      iv: string | Buffer | null,
      inputEncoding?: crypto.Encoding,
      outputEncoding?: crypto.Encoding
    ) => {
      const key = crypto.scryptSync(this.password, this.salt, this.keylen);
      const cipher = crypto.createCipheriv(this.algorithm, key, iv);

      if (!inputEncoding) {
        inputEncoding = 'utf8';
      }

      if (!outputEncoding) {
        outputEncoding = 'hex';
      }

      let encrypted = cipher.update(text, inputEncoding, outputEncoding);
      encrypted = encrypted + cipher.final(outputEncoding);

      return encrypted;
    },
    buffer: (text: Buffer, iv: string | Buffer | null) => {
      const key = crypto.scryptSync(this.password, this.salt, this.keylen);
      const cipher = crypto.createCipheriv(this.algorithm, key, iv);

      let encrypted = cipher.update(text);
      encrypted = Buffer.concat([encrypted, cipher.final()]);

      return encrypted;
    },
  };

  decrypt = {
    binary(text: string, iv: string | Buffer | null, outputEncoding?: crypto.Encoding) {
      return this.string(text, iv, 'binary', outputEncoding);
    },
    hex(text: string, iv: string | Buffer | null, outputEncoding?: crypto.Encoding) {
      return this.string(text, iv, 'hex', outputEncoding);
    },
    base64(text: string, iv: string | Buffer | null, outputEncoding?: crypto.Encoding) {
      return this.string(text, iv, 'base64', outputEncoding);
    },
    uint8Array(text: Buffer, iv: string | Buffer | null) {
      const buffer = this.buffer(text, iv);
      return new Uint8Array(buffer);
    },
    string: (
      text: string,
      iv: string | Buffer | null,
      inputEncoding?: crypto.Encoding,
      outputEncoding?: crypto.Encoding
    ) => {
      const key = crypto.scryptSync(this.password, this.salt, this.keylen);
      const decipher = crypto.createDecipheriv(this.algorithm, key, iv);

      if (!inputEncoding) {
        inputEncoding = 'hex';
      }

      if (!outputEncoding) {
        outputEncoding = 'utf8';
      }

      let decrypted = decipher.update(text, inputEncoding, outputEncoding);
      decrypted = decrypted + decipher.final(outputEncoding);

      return decrypted;
    },
    buffer: (text: Buffer, iv: string | Buffer | null) => {
      const key = crypto.scryptSync(this.password, this.salt, this.keylen);
      const decipher = crypto.createDecipheriv(this.algorithm, key, iv);

      let decrypted = decipher.update(text);
      decrypted = Buffer.concat([decrypted, decipher.final()]);

      return decrypted;
    },
  };
}
