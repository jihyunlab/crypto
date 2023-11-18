import * as crypto from 'crypto';

export class Aead {
  private algorithm: crypto.CipherCCMTypes | crypto.CipherGCMTypes;
  private key: string | Buffer;
  private authTagLength?: number;
  private aad?: Buffer;

  constructor(
    algorithm: crypto.CipherCCMTypes | crypto.CipherGCMTypes,
    key: string | Buffer,
    authTagLength?: number,
    aad?: Buffer
  ) {
    this.algorithm = algorithm;
    this.key = key;
    this.authTagLength = authTagLength;
    this.aad = aad;
  }

  encrypt = {
    binary(text: string, nonce: string | Buffer, inputEncoding?: crypto.Encoding) {
      if (!inputEncoding) {
        inputEncoding = 'utf8';
      }

      const string = this.string(text, nonce, inputEncoding, 'binary');
      return { text: string.text, tag: string.tag };
    },
    hex(text: string, nonce: string | Buffer, inputEncoding?: crypto.Encoding) {
      if (!inputEncoding) {
        inputEncoding = 'utf8';
      }

      const string = this.string(text, nonce, inputEncoding, 'hex');
      return { text: string.text, tag: string.tag };
    },
    base64(text: string, nonce: string | Buffer, inputEncoding?: crypto.Encoding) {
      if (!inputEncoding) {
        inputEncoding = 'utf8';
      }

      const string = this.string(text, nonce, inputEncoding, 'base64');
      return { text: string.text, tag: string.tag };
    },
    uint8Array(text: Buffer, nonce: string | Buffer) {
      const buffer = this.buffer(text, nonce);
      return { text: new Uint8Array(buffer.text), tag: buffer.tag };
    },
    string: (
      text: string,
      nonce: string | Buffer,
      inputEncoding?: crypto.Encoding,
      outputEncoding?: crypto.Encoding
    ) => {
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

      if (!inputEncoding) {
        inputEncoding = 'utf8';
      }

      if (!outputEncoding) {
        outputEncoding = 'hex';
      }

      if (this.aad) {
        cipher.setAAD(this.aad, {
          plaintextLength: Buffer.from(text, inputEncoding as BufferEncoding).length,
        });
      }

      let encrypted = cipher.update(text, inputEncoding, outputEncoding);
      encrypted = encrypted + cipher.final(outputEncoding);

      const authTag = cipher.getAuthTag();

      return { text: encrypted, tag: authTag };
    },
    buffer: (text: Buffer, nonce: string | Buffer) => {
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

      return { text: encrypted, tag: authTag };
    },
  };

  decrypt = {
    binary(text: string, tag: Buffer, nonce: string | Buffer, outputEncoding?: crypto.Encoding) {
      return this.string(text, tag, nonce, 'binary', outputEncoding);
    },
    hex(text: string, tag: Buffer, nonce: string | Buffer, outputEncoding?: crypto.Encoding) {
      return this.string(text, tag, nonce, 'hex', outputEncoding);
    },
    base64(text: string, tag: Buffer, nonce: string | Buffer, outputEncoding?: crypto.Encoding) {
      return this.string(text, tag, nonce, 'base64', outputEncoding);
    },
    uint8Array(text: Uint8Array, tag: Buffer, nonce: string | Buffer) {
      const buffer = this.buffer(Buffer.from(text), tag, nonce);
      return buffer;
    },
    string: (
      text: string,
      tag: Buffer,
      nonce: string | Buffer,
      inputEncoding?: crypto.Encoding,
      outputEncoding?: crypto.Encoding
    ) => {
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

      if (!inputEncoding) {
        inputEncoding = 'hex';
      }

      if (!outputEncoding) {
        outputEncoding = 'utf8';
      }

      decipher.setAuthTag(tag);

      if (this.aad) {
        decipher.setAAD(this.aad, {
          plaintextLength: Buffer.from(text, inputEncoding as BufferEncoding).length,
        });
      }

      let decrypted = decipher.update(text, inputEncoding, outputEncoding);
      decrypted = decrypted + decipher.final(outputEncoding);

      return decrypted;
    },
    buffer: (text: Buffer, tag: Buffer, nonce: string | Buffer) => {
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
