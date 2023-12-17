import * as crypto from 'crypto';

const KEYPAIR = {
  RSA: 'rsa',
  RSA_PSS: 'rsa-pss',
  DSA: 'dsa',
  EC: 'ec',
  ED25519: 'ed25519',
  ED448: 'ed448',
  X25519: 'x25519',
  X448: 'x448',
} as const;
type KEYPAIR = (typeof KEYPAIR)[keyof typeof KEYPAIR];

export const CURVE = {
  P256: 'prime256v1',
  P384: 'secp384r1',
  PRIME256V1: 'prime256v1',
  SECP256K1: 'secp256k1',
  SECP384R1: 'secp384r1',
  BRAINPOOLP256R1: 'brainpoolP256r1',
  BRAINPOOLP384R1: 'brainpoolP384r1',
  BRAINPOOLP512R1: 'brainpoolP512r1',
  SM2: 'SM2',
} as const;
export type CURVE = (typeof CURVE)[keyof typeof CURVE];

export const KeyPair = {
  generate: {
    secretKey(key: Buffer) {
      return crypto.createSecretKey(key);
    },

    privateKey(key: string | Buffer | crypto.PrivateKeyInput | crypto.JsonWebKeyInput) {
      return crypto.createPrivateKey(key);
    },

    publicKey(key: string | Buffer | crypto.PublicKeyInput | crypto.JsonWebKeyInput | crypto.KeyObject) {
      return crypto.createPublicKey(key);
    },

    rsa(
      options:
        | crypto.RSAKeyPairKeyObjectOptions
        | crypto.RSAKeyPairOptions<'pem', 'pem'>
        | crypto.RSAKeyPairOptions<'pem', 'der'>
        | crypto.RSAKeyPairOptions<'der', 'pem'>
        | crypto.RSAKeyPairOptions<'der', 'der'>
    ) {
      return crypto.generateKeyPairSync(KEYPAIR.RSA, options);
    },

    rsapss(
      options:
        | crypto.RSAPSSKeyPairKeyObjectOptions
        | crypto.RSAPSSKeyPairOptions<'pem', 'pem'>
        | crypto.RSAPSSKeyPairOptions<'pem', 'der'>
        | crypto.RSAPSSKeyPairOptions<'der', 'pem'>
        | crypto.RSAPSSKeyPairOptions<'der', 'der'>
    ) {
      return crypto.generateKeyPairSync(KEYPAIR.RSA_PSS, options);
    },

    dsa(
      options:
        | crypto.DSAKeyPairKeyObjectOptions
        | crypto.DSAKeyPairOptions<'pem', 'pem'>
        | crypto.DSAKeyPairOptions<'pem', 'der'>
        | crypto.DSAKeyPairOptions<'der', 'pem'>
        | crypto.DSAKeyPairOptions<'der', 'der'>
    ) {
      return crypto.generateKeyPairSync(KEYPAIR.DSA, options);
    },

    ec(
      options:
        | crypto.ECKeyPairKeyObjectOptions
        | crypto.ECKeyPairOptions<'pem', 'pem'>
        | crypto.ECKeyPairOptions<'pem', 'der'>
        | crypto.ECKeyPairOptions<'der', 'pem'>
        | crypto.ECKeyPairOptions<'der', 'der'>
    ) {
      return crypto.generateKeyPairSync(KEYPAIR.EC, options);
    },

    ed25519(
      options:
        | crypto.ED25519KeyPairKeyObjectOptions
        | crypto.ED25519KeyPairOptions<'pem', 'pem'>
        | crypto.ED25519KeyPairOptions<'pem', 'der'>
        | crypto.ED25519KeyPairOptions<'der', 'pem'>
        | crypto.ED25519KeyPairOptions<'der', 'der'>
    ) {
      return crypto.generateKeyPairSync(KEYPAIR.ED25519, options);
    },

    ed448(
      options:
        | crypto.ED448KeyPairKeyObjectOptions
        | crypto.ED448KeyPairOptions<'pem', 'pem'>
        | crypto.ED448KeyPairOptions<'pem', 'der'>
        | crypto.ED448KeyPairOptions<'der', 'pem'>
        | crypto.ED448KeyPairOptions<'der', 'der'>
    ) {
      return crypto.generateKeyPairSync(KEYPAIR.ED448, options);
    },

    x25519(
      options:
        | crypto.X25519KeyPairKeyObjectOptions
        | crypto.X25519KeyPairOptions<'pem', 'pem'>
        | crypto.X25519KeyPairOptions<'pem', 'der'>
        | crypto.X25519KeyPairOptions<'der', 'pem'>
        | crypto.X25519KeyPairOptions<'der', 'der'>
    ) {
      return crypto.generateKeyPairSync(KEYPAIR.X25519, options);
    },

    x448(
      options:
        | crypto.X448KeyPairKeyObjectOptions
        | crypto.X448KeyPairOptions<'pem', 'pem'>
        | crypto.X448KeyPairOptions<'pem', 'der'>
        | crypto.X448KeyPairOptions<'der', 'pem'>
        | crypto.X448KeyPairOptions<'der', 'der'>
    ) {
      return crypto.generateKeyPairSync(KEYPAIR.X448, options);
    },

    // EC presets
    p256() {
      return crypto.generateKeyPairSync(KEYPAIR.EC, { namedCurve: CURVE.P256 });
    },

    p384() {
      return crypto.generateKeyPairSync(KEYPAIR.EC, { namedCurve: CURVE.P384 });
    },

    brainpoolP256() {
      return crypto.generateKeyPairSync(KEYPAIR.EC, { namedCurve: CURVE.BRAINPOOLP256R1 });
    },

    brainpoolP384() {
      return crypto.generateKeyPairSync(KEYPAIR.EC, { namedCurve: CURVE.BRAINPOOLP384R1 });
    },

    sm2() {
      return crypto.generateKeyPairSync(KEYPAIR.EC, { namedCurve: CURVE.SM2 });
    },
  },
};
