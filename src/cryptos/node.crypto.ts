import { Crypto, ExtendedJsonWebKey } from '../interfaces/crypto.interface';
import * as crypto from 'crypto';

export class NodeCrypto implements Crypto {
  private readonly keyType: 'rsa';
  private readonly signingAlgorithm: string;
  private readonly jwkKeyType: string;
  private readonly jwkAlgorithm: string;
  private readonly jwkUse: string;
  private readonly modulusLength?: number;

  private constructor(
    keyType: 'rsa',
    signingAlgorithm: string,
    jwkKeyType: string,
    jwkAlgorithm: string,
    jwkUse: string,
    modulusLength?: number
  ) {
    this.keyType = keyType;
    this.signingAlgorithm = signingAlgorithm;
    this.jwkKeyType = jwkKeyType;
    this.jwkAlgorithm = jwkAlgorithm;
    this.jwkUse = jwkUse;

    if (modulusLength !== undefined && modulusLength !== null) {
      this.modulusLength = modulusLength;
    }
  }

  public static async create(
    keyType: 'rsa',
    signingAlgorithm: string,
    jwkKeyType: string,
    jwkAlgorithm: string,
    jwkUse: string,
    modulusLength?: number
  ) {
    const instance = new NodeCrypto(
      keyType,
      signingAlgorithm,
      jwkKeyType,
      jwkAlgorithm,
      jwkUse,
      modulusLength
    );

    return instance;
  }

  public async generateKeyPair() {
    const keyPair = crypto.generateKeyPairSync(this.keyType, {
      modulusLength: this.modulusLength || 4096,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    return keyPair;
  }

  public async createPrivateKeyFromPem(pem: string) {
    return crypto.createPrivateKey({
      key: pem,
      format: 'pem',
      type: 'pkcs8',
    });
  }

  public async createPublicKeyFromPem(pem: string) {
    return crypto.createPublicKey({
      key: pem,
      format: 'pem',
      type: 'spki',
    });
  }

  public async createJwk(kid: string, key: crypto.KeyObject) {
    const jwkFromPublicKey = key.export({ format: 'jwk' });

    const jwk = {
      kty: this.jwkKeyType,
      alg: this.jwkAlgorithm,
      use: this.jwkUse,
      kid: kid,
      n: jwkFromPublicKey['n'],
      e: jwkFromPublicKey['e'],
    };

    return jwk;
  }

  public async createPublicKeyFromJwk(jwk: ExtendedJsonWebKey) {
    return crypto.createPublicKey({ key: jwk as any, format: 'jwk' });
  }

  public async sign(
    privateKey:
      | crypto.KeyLike
      | crypto.SignKeyObjectInput
      | crypto.SignPrivateKeyInput,
    toBeSigned: Uint8Array
  ) {
    const signer = crypto.createSign(this.signingAlgorithm);

    signer.update(toBeSigned);
    signer.end();

    return signer.sign(privateKey);
  }

  public async verify(
    publicKey: crypto.KeyLike | crypto.SignKeyObjectInput,
    toBeSigned: Uint8Array,
    signature: Uint8Array
  ) {
    const verifier = crypto.createVerify(this.signingAlgorithm);

    verifier.update(toBeSigned);
    verifier.end();

    return verifier.verify(publicKey, signature);
  }
}
