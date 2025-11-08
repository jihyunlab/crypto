import { Hash } from '../interfaces/hash.interface';
import * as crypto from 'crypto';

export class NodeCryptoHash implements Hash {
  private readonly hash: string;

  private constructor(hash: string) {
    this.hash = hash;
  }

  public static async create(cipher: string) {
    const instance = new NodeCryptoHash(cipher);

    return instance;
  }

  public async digest(input: Uint8Array) {
    const buffer = crypto.createHash(this.hash).update(input).digest();

    return new Uint8Array(buffer);
  }
}
