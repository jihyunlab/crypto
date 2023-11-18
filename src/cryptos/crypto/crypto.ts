import * as crypto from 'crypto';

export class Crypto {
  private algorithm: string;
  private password: string | Buffer;
  private salt: string | Buffer;
  private cipherInfo: crypto.CipherInfo;

  constructor(algorithm: string, password: string | Buffer, salt: string | Buffer) {
    this.algorithm = algorithm;
    this.password = password;
    this.salt = salt;

    const info = crypto.getCipherInfo(this.algorithm);

    if (!info) {
      throw new Error('cipher information not found.');
    }

    this.cipherInfo = info;
  }

  info() {
    return this.cipherInfo;
  }

  generateIv(iv?: string | Buffer) {
    let generated: string | Buffer | null;

    if (!iv) {
      generated = null;

      if (this.cipherInfo.ivLength !== undefined && this.cipherInfo.ivLength > 0) {
        generated = Buffer.from(crypto.randomFillSync(new Uint8Array(this.cipherInfo.ivLength)));
      }

      return generated;
    }

    generated = iv;

    if (!this.cipherInfo.ivLength) {
      generated = null;
    } else {
      if (typeof iv === 'string') {
        if (this.cipherInfo.ivLength !== Buffer.from(iv, 'utf8').length) {
          const buffer = Buffer.alloc(this.cipherInfo.ivLength);
          generated = Buffer.concat([Buffer.from(iv, 'utf8'), buffer]).subarray(0, this.cipherInfo.ivLength);
          generated = generated.toString('utf8');
        }
      } else {
        if (this.cipherInfo.ivLength !== iv.length) {
          const buffer = Buffer.alloc(this.cipherInfo.ivLength);
          generated = Buffer.concat([Buffer.from(iv), buffer]).subarray(0, this.cipherInfo.ivLength);
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
      const key = crypto.scryptSync(this.password, this.salt, this.cipherInfo.keyLength);
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
      const key = crypto.scryptSync(this.password, this.salt, this.cipherInfo.keyLength);
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
    uint8Array(text: Uint8Array, iv: string | Buffer | null) {
      const buffer = this.buffer(Buffer.from(text), iv);
      return buffer;
    },
    string: (
      text: string,
      iv: string | Buffer | null,
      inputEncoding?: crypto.Encoding,
      outputEncoding?: crypto.Encoding
    ) => {
      const key = crypto.scryptSync(this.password, this.salt, this.cipherInfo.keyLength);
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
      const key = crypto.scryptSync(this.password, this.salt, this.cipherInfo.keyLength);
      const decipher = crypto.createDecipheriv(this.algorithm, key, iv);

      let decrypted = decipher.update(text);
      decrypted = Buffer.concat([decrypted, decipher.final()]);

      return decrypted;
    },
  };
}
