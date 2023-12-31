import * as crypto from 'crypto';

export class Signer {
  private algorithm: string | null | undefined;
  private key: crypto.KeyLike | crypto.SignKeyObjectInput | crypto.SignPrivateKeyInput;

  constructor(
    key: crypto.KeyLike | crypto.SignKeyObjectInput | crypto.SignPrivateKeyInput,
    algorithm: string | null | undefined = null
  ) {
    this.key = key;
    this.algorithm = algorithm;
  }

  sign(message: Buffer) {
    return crypto.sign(this.algorithm, message, this.key);
  }
}
