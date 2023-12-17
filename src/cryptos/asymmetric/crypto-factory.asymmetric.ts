import { Signer } from './signer.asymmetric';
import { Verifier } from './verifier.asymmetric';
import { PrivateCipher } from './private-cipher.asymmetric';
import { PublicCipher } from './public-cipher.asymmetric';
import * as crypto from 'crypto';

export const createSigner = (key: crypto.KeyObject) => {
  return new Signer(key);
};

export const createVerifier = (key: crypto.KeyObject) => {
  return new Verifier(key);
};

export const createPrivateCipher = (key: crypto.RsaPrivateKey | crypto.KeyLike) => {
  return new PrivateCipher(key);
};

export const createPublicCipher = (key: crypto.RsaPublicKey | crypto.KeyLike) => {
  return new PublicCipher(key);
};
