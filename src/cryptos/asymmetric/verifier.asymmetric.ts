import * as crypto from 'crypto';

export class Verifier {
  private algorithm: string | null | undefined;
  private key:
    | crypto.KeyLike
    | crypto.VerifyKeyObjectInput
    | crypto.VerifyPublicKeyInput
    | crypto.VerifyJsonWebKeyInput;

  constructor(
    key: crypto.KeyLike | crypto.VerifyKeyObjectInput | crypto.VerifyPublicKeyInput | crypto.VerifyJsonWebKeyInput,
    algorithm: string | null | undefined = null
  ) {
    this.key = key;
    this.algorithm = algorithm;
  }

  verify(message: Buffer, signature: Buffer) {
    return crypto.verify(this.algorithm, message, this.key, signature);
  }
}
