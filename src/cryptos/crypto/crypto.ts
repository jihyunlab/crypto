import * as crypto from 'crypto';
import { HASH } from '../hash/hash.factory';

export class Crypto {
  private algorithm: string;
  private key: string | Buffer;
  private cipherInfo: crypto.CipherInfo;

  constructor(
    algorithm: string,
    password: string | Buffer,
    salt: string | Buffer,
    pbkdf2 = true,
    rounds = 1024,
    hash: HASH = HASH.SHA_512
  ) {
    this.algorithm = algorithm;

    const info = crypto.getCipherInfo(this.algorithm);

    if (!info) {
      throw new Error('cipher information not found.');
    }

    this.cipherInfo = info;
    this.key = this.generateKey(password, salt, pbkdf2, rounds, hash);
  }

  private generateKey(password: string | Buffer, salt: string | Buffer, pbkdf2: boolean, rounds: number, hash: HASH) {
    if (pbkdf2) {
      return crypto.pbkdf2Sync(password, salt, rounds, this.cipherInfo.keyLength, hash);
    } else {
      return crypto.scryptSync(password, salt, this.cipherInfo.keyLength);
    }
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
