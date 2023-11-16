import * as crypto from 'crypto';

export class Aead {
  private algorithm: crypto.CipherCCMTypes | crypto.CipherGCMTypes;
  private key: string | Buffer;
  private nonce: string | Buffer;
  private authTagLength?: number;
  private aad?: Buffer;

  constructor(
    algorithm: crypto.CipherCCMTypes | crypto.CipherGCMTypes,
    key: string | Buffer,
    nonce?: string | Buffer,
    authTagLength?: number,
    aad?: Buffer
  ) {
    this.algorithm = algorithm;
    this.key = key;
    this.authTagLength = authTagLength;
    this.aad = aad;

    if (nonce) {
      this.nonce = nonce;
    } else {
      const info = crypto.getCipherInfo(this.algorithm);

      if (info && info.ivLength !== undefined && info.ivLength > 0) {
        this.nonce = crypto.randomBytes(info.ivLength);
      } else {
        throw new Error('nonce cannot be generated automatically.');
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
      return { text: new Uint8Array(buffer.text), nonce: buffer.nonce };
    },
    string: (
      text: string,
      inputEncoding?: 'base64' | 'base64url' | 'hex' | 'binary' | 'utf8' | 'utf-8' | 'utf16le' | 'utf-16le' | 'latin1',
      outputEncoding?: 'base64' | 'base64url' | 'hex' | 'binary' | 'utf8' | 'utf-8' | 'utf16le' | 'utf-16le' | 'latin1'
    ) => {
      const info = crypto.getCipherInfo(this.algorithm);

      let nonce = this.nonce;

      if (nonce && info) {
        if (info.ivLength !== undefined && info.ivLength > 0 && nonce.length !== info.ivLength) {
          if (typeof nonce === 'string') {
            nonce = nonce + '0'.repeat(info.ivLength);
            nonce = nonce.slice(0, info.ivLength);
          } else {
            const buffer = Buffer.alloc(info.ivLength);
            nonce = Buffer.concat([Buffer.from(nonce), buffer]).subarray(0, info.ivLength);
          }
        }
      }

      let cipher: crypto.CipherCCM | crypto.CipherGCM;

      if (this.algorithm as crypto.CipherCCMTypes) {
        let authTagLength = this.authTagLength;

        if (!authTagLength) {
          authTagLength = 16;
        }

        cipher = crypto.createCipheriv(this.algorithm as crypto.CipherCCMTypes, this.key, nonce, {
          authTagLength: authTagLength,
        });
      } else if (this.algorithm as crypto.CipherGCMTypes) {
        cipher = crypto.createCipheriv(this.algorithm as crypto.CipherGCMTypes, this.key, nonce, {
          authTagLength: this.authTagLength,
        });
      } else {
        throw new Error('cipher not found. please check the algorithm.');
      }

      if (this.aad) {
        cipher.setAAD(this.aad, {
          plaintextLength: Buffer.byteLength(text),
        });
      }

      if (!inputEncoding) {
        inputEncoding = 'utf-8';
      }

      if (!outputEncoding) {
        outputEncoding = 'hex';
      }

      let encrypted = cipher.update(text, inputEncoding, outputEncoding);
      encrypted = encrypted + cipher.final(outputEncoding);

      const authTag = cipher.getAuthTag();

      return { text: encrypted, nonce: this.nonce, tag: authTag };
    },
    buffer: (text: Buffer) => {
      const info = crypto.getCipherInfo(this.algorithm);

      let nonce = this.nonce;

      if (nonce && info) {
        if (info.ivLength !== undefined && info.ivLength > 0 && nonce.length !== info.ivLength) {
          if (typeof nonce === 'string') {
            nonce = nonce + '0'.repeat(info.ivLength);
            nonce = nonce.slice(0, info.ivLength);
          } else {
            const buffer = Buffer.alloc(info.ivLength);
            nonce = Buffer.concat([Buffer.from(nonce), buffer]).subarray(0, info.ivLength);
          }
        }
      }

      let cipher: crypto.CipherCCM | crypto.CipherGCM;

      if (this.algorithm as crypto.CipherCCMTypes) {
        let authTagLength = this.authTagLength;

        if (!authTagLength) {
          authTagLength = 16;
        }

        cipher = crypto.createCipheriv(this.algorithm as crypto.CipherCCMTypes, this.key, nonce, {
          authTagLength: authTagLength,
        });
      } else if (this.algorithm as crypto.CipherGCMTypes) {
        cipher = crypto.createCipheriv(this.algorithm as crypto.CipherGCMTypes, this.key, nonce, {
          authTagLength: this.authTagLength,
        });
      } else {
        throw new Error('cipher not found. please check the algorithm.');
      }

      if (this.aad) {
        cipher.setAAD(this.aad, {
          plaintextLength: text.length,
        });
      }

      let encrypted = cipher.update(text);
      encrypted = Buffer.concat([encrypted, cipher.final()]);

      const authTag = cipher.getAuthTag();

      return { text: encrypted, nonce: this.nonce, tag: authTag };
    },
  };

  decrypt = {
    binary(
      text: string,
      tag: Buffer,
      outputEncoding?: 'base64' | 'base64url' | 'hex' | 'binary' | 'utf8' | 'utf-8' | 'utf16le' | 'utf-16le' | 'latin1'
    ) {
      return this.string(text, tag, 'binary', outputEncoding);
    },
    hex(
      text: string,
      tag: Buffer,
      outputEncoding?: 'base64' | 'base64url' | 'hex' | 'binary' | 'utf8' | 'utf-8' | 'utf16le' | 'utf-16le' | 'latin1'
    ) {
      return this.string(text, tag, 'hex', outputEncoding);
    },
    base64(
      text: string,
      tag: Buffer,
      outputEncoding?: 'base64' | 'base64url' | 'hex' | 'binary' | 'utf8' | 'utf-8' | 'utf16le' | 'utf-16le' | 'latin1'
    ) {
      return this.string(text, tag, 'base64', outputEncoding);
    },
    uint8Array(text: Buffer, tag: Buffer) {
      const buffer = this.buffer(text, tag);
      return new Uint8Array(buffer);
    },
    string: (
      text: string,
      tag: Buffer,
      inputEncoding?: 'base64' | 'base64url' | 'hex' | 'binary' | 'utf8' | 'utf-8' | 'utf16le' | 'utf-16le' | 'latin1',
      outputEncoding?: 'base64' | 'base64url' | 'hex' | 'binary' | 'utf8' | 'utf-8' | 'utf16le' | 'utf-16le' | 'latin1'
    ) => {
      const info = crypto.getCipherInfo(this.algorithm);

      let nonce = this.nonce;

      if (nonce && info) {
        if (info.ivLength !== undefined && info.ivLength > 0 && nonce.length !== info.ivLength) {
          if (typeof nonce === 'string') {
            nonce = nonce + '0'.repeat(info.ivLength);
            nonce = nonce.slice(0, info.ivLength);
          } else {
            const buffer = Buffer.alloc(info.ivLength);
            nonce = Buffer.concat([Buffer.from(nonce), buffer]).subarray(0, info.ivLength);
          }
        }
      }

      let decipher: crypto.DecipherCCM | crypto.DecipherGCM;

      if (this.algorithm as crypto.CipherCCMTypes) {
        let authTagLength = this.authTagLength;

        if (!authTagLength) {
          authTagLength = 16;
        }

        decipher = crypto.createDecipheriv(this.algorithm as crypto.CipherCCMTypes, this.key, nonce, {
          authTagLength: authTagLength,
        });
      } else if (this.algorithm as crypto.CipherGCMTypes) {
        decipher = crypto.createDecipheriv(this.algorithm as crypto.CipherGCMTypes, this.key, nonce, {
          authTagLength: this.authTagLength,
        });
      } else {
        throw new Error('decipher not found. please check the algorithm.');
      }

      decipher.setAuthTag(tag);

      if (this.aad) {
        decipher.setAAD(this.aad, {
          plaintextLength: Buffer.byteLength(text),
        });
      }

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
    buffer: (text: Buffer, tag: Buffer) => {
      const info = crypto.getCipherInfo(this.algorithm);

      let nonce = this.nonce;

      if (nonce && info) {
        if (info.ivLength !== undefined && info.ivLength > 0 && nonce.length !== info.ivLength) {
          if (typeof nonce === 'string') {
            nonce = nonce + '0'.repeat(info.ivLength);
            nonce = nonce.slice(0, info.ivLength);
          } else {
            const buffer = Buffer.alloc(info.ivLength);
            nonce = Buffer.concat([Buffer.from(nonce), buffer]).subarray(0, info.ivLength);
          }
        }
      }

      let decipher: crypto.DecipherCCM | crypto.DecipherGCM;

      if (this.algorithm as crypto.CipherCCMTypes) {
        let authTagLength = this.authTagLength;

        if (!authTagLength) {
          authTagLength = 16;
        }

        decipher = crypto.createDecipheriv(this.algorithm as crypto.CipherCCMTypes, this.key, nonce, {
          authTagLength: authTagLength,
        });
      } else if (this.algorithm as crypto.CipherGCMTypes) {
        decipher = crypto.createDecipheriv(this.algorithm as crypto.CipherGCMTypes, this.key, nonce, {
          authTagLength: this.authTagLength,
        });
      } else {
        throw new Error('decipher not found. please check the algorithm.');
      }

      decipher.setAuthTag(tag);

      if (this.aad) {
        decipher.setAAD(this.aad, {
          plaintextLength: text.length,
        });
      }

      let decrypted = decipher.update(text);
      decrypted = Buffer.concat([decrypted, decipher.final()]);

      return decrypted;
    },
  };
}
