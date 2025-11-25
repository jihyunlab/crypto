import { Cipher, CipherOptions } from '../interfaces/cipher.interface';
import { KeyHelper } from '../helpers/key.helper';
import * as crypto from 'crypto';

export class NodeCipher implements Cipher {
  private readonly cipher: string;
  private readonly ivLength: number;
  private readonly key: Buffer;
  private readonly tagLength?: number;
  private readonly additionalData?: Uint8Array;

  private constructor(
    cipher: string,
    key: Buffer,
    ivLength: number,
    tagLength?: number,
    additionalData?: Uint8Array
  ) {
    this.cipher = cipher;
    this.key = key;
    this.ivLength = ivLength;
    this.tagLength = tagLength;
    this.additionalData = additionalData;
  }

  public static async create(
    cipher: string,
    length: number,
    password: string,
    ivLength: number,
    tagLength?: number,
    additionalData?: Uint8Array,
    options?: CipherOptions
  ) {
    let salt = '';
    let iterations = 128;

    if (options && options.salt) {
      salt = options.salt;
    }

    if (
      options &&
      options.iterations !== undefined &&
      options.iterations !== null
    ) {
      iterations = options.iterations;
    }

    const key = await KeyHelper.pbkdf2(length / 8, password, salt, iterations);

    const instance = new NodeCipher(
      cipher,
      key,
      ivLength,
      tagLength,
      additionalData
    );

    return instance;
  }

  public async encrypt(text: string | Uint8Array) {
    if (!this.key) {
      throw new Error('key does not exist.');
    }

    const iv = Buffer.from(
      crypto.randomFillSync(new Uint8Array(this.ivLength))
    );

    let buffer: Buffer;

    if (typeof text === 'string') {
      buffer = Buffer.from(text, 'utf8');
    } else {
      buffer = Buffer.from(text);
    }

    let encrypted: Buffer;

    if (this.cipher === 'aes-256-gcm') {
      const cipher = crypto.createCipheriv(
        this.cipher,
        new Uint8Array(this.key),
        new Uint8Array(iv),
        {
          authTagLength: this.tagLength || 16,
        }
      );

      if (this.additionalData !== undefined && this.additionalData !== null) {
        cipher.setAAD(this.additionalData, {
          plaintextLength: buffer.length,
        });
      }

      encrypted = cipher.update(new Uint8Array(buffer));

      const final = cipher.final();
      encrypted = Buffer.concat([
        new Uint8Array(iv),
        new Uint8Array(encrypted),
        new Uint8Array(final),
        new Uint8Array(cipher.getAuthTag()),
      ]);
    } else {
      const cipher = crypto.createCipheriv(
        this.cipher,
        new Uint8Array(this.key),
        new Uint8Array(iv)
      );

      encrypted = cipher.update(new Uint8Array(buffer));
      encrypted = Buffer.concat([
        new Uint8Array(iv),
        new Uint8Array(encrypted),
        new Uint8Array(cipher.final()),
      ]);
    }

    return new Uint8Array(encrypted);
  }

  public async decrypt(text: string | Uint8Array) {
    if (!this.key) {
      throw new Error('key does not exist.');
    }

    let buffer: Buffer;

    if (typeof text === 'string') {
      buffer = Buffer.from(text, 'hex');
    } else {
      buffer = Buffer.from(text);
    }

    let decrypted: Buffer;
    const iv = buffer.subarray(0, this.ivLength);

    if (this.cipher === 'aes-256-gcm') {
      const tagLength = this.tagLength || 16;
      const tag = buffer.subarray(buffer.length - tagLength, buffer.length);

      buffer = buffer.subarray(this.ivLength, buffer.length - tagLength);

      const decipher = crypto.createDecipheriv(
        this.cipher,
        new Uint8Array(this.key),
        new Uint8Array(iv),
        {
          authTagLength: tagLength,
        }
      );

      decipher.setAuthTag(new Uint8Array(tag));

      if (this.additionalData !== undefined && this.additionalData !== null) {
        decipher.setAAD(this.additionalData, {
          plaintextLength: buffer.length,
        });
      }

      decrypted = decipher.update(new Uint8Array(buffer));
      decrypted = Buffer.concat([
        new Uint8Array(decrypted),
        new Uint8Array(decipher.final()),
      ]);
    } else {
      buffer = buffer.subarray(this.ivLength);

      const decipher = crypto.createDecipheriv(
        this.cipher,
        new Uint8Array(this.key),
        new Uint8Array(iv)
      );

      decrypted = decipher.update(new Uint8Array(buffer));
      decrypted = Buffer.concat([
        new Uint8Array(decrypted),
        new Uint8Array(decipher.final()),
      ]);
    }

    return new Uint8Array(decrypted);
  }
}
