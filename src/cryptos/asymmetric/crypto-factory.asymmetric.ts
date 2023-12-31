import { Signer } from './signer.asymmetric';
import { Verifier } from './verifier.asymmetric';
import { PrivateCipher } from './private-cipher.asymmetric';
import { PublicCipher } from './public-cipher.asymmetric';
import * as crypto from 'crypto';

export const createSigner = (
  key: crypto.KeyLike | crypto.SignKeyObjectInput | crypto.SignPrivateKeyInput,
  algorithm: string | null | undefined = null
) => {
  return new Signer(key, algorithm);
};

export const createVerifier = (
  key: crypto.KeyLike | crypto.VerifyKeyObjectInput | crypto.VerifyPublicKeyInput | crypto.VerifyJsonWebKeyInput,
  algorithm: string | null | undefined = null
) => {
  return new Verifier(key, algorithm);
};

export const createPrivateCipher = (key: crypto.RsaPrivateKey | crypto.KeyLike) => {
  return new PrivateCipher(key);
};

export const createPublicCipher = (key: crypto.RsaPublicKey | crypto.KeyLike) => {
  return new PublicCipher(key);
};
