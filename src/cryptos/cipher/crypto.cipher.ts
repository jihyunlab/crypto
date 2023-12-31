import * as crypto from 'crypto';

export class Cipher {
  private algorithm: string;
  private key: string | Buffer;

  constructor(algorithm: string, key: string | Buffer) {
    this.algorithm = algorithm;
    this.key = key;
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

    base64url(text: string, iv: string | Buffer | null, inputEncoding?: crypto.Encoding) {
      if (!inputEncoding) {
        inputEncoding = 'utf8';
      }

      return this.string(text, iv, inputEncoding, 'base64url');
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
      const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);

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
      const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);

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

    base64url(text: string, iv: string | Buffer | null, outputEncoding?: crypto.Encoding) {
      return this.string(text, iv, 'base64url', outputEncoding);
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
      const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);

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
      const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);

      let decrypted = decipher.update(text);
      decrypted = Buffer.concat([decrypted, decipher.final()]);

      return decrypted;
    },
  };
}
