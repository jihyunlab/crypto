import { Asymmetric, CURVE, Helper } from '../../src/index';
import * as crypto from 'crypto';

describe('Asymmetric', () => {
  const passphrase = 'passphrase';
  const message = Buffer.from('Welcome to JihyunLab.', 'utf8');

  const rsaCipherKeypair = Helper.keyPair.generate.rsa({
    modulusLength: 4096,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase: passphrase,
    },
  });

  test('privateCipher(rsa)', () => {
    const privateCipher = Asymmetric.create.privateCipher({
      key: rsaCipherKeypair.privateKey,
      passphrase: passphrase,
    });

    const publicCipher = Asymmetric.create.publicCipher(rsaCipherKeypair.publicKey);

    const encrypted = privateCipher.encrypt(message);
    const decrypted = publicCipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(message);
  });

  test('publicCipher(rsa)', () => {
    const privateCipher = Asymmetric.create.privateCipher({
      key: rsaCipherKeypair.privateKey,
      passphrase: passphrase,
    });

    const publicCipher = Asymmetric.create.publicCipher({
      key: rsaCipherKeypair.publicKey,
    });

    const encrypted = publicCipher.encrypt(message);
    const decrypted = privateCipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(message);
  });

  test('ec presets', () => {
    // p256
    let keyPair = Helper.keyPair.generate.p256();

    let signer = Asymmetric.create.signer(keyPair.privateKey);
    let verifier = Asymmetric.create.verifier(keyPair.publicKey);

    let signature = signer.sign(message);
    let verify = verifier.verify(message, signature);

    expect(verify).toBe(true);

    // p384
    keyPair = Helper.keyPair.generate.p384();

    signer = Asymmetric.create.signer(keyPair.privateKey);
    verifier = Asymmetric.create.verifier(keyPair.publicKey);

    signature = signer.sign(message);
    verify = verifier.verify(message, signature);

    expect(verify).toBe(true);

    // brainpoolP256
    keyPair = Helper.keyPair.generate.brainpoolP256();

    signer = Asymmetric.create.signer(keyPair.privateKey);
    verifier = Asymmetric.create.verifier(keyPair.publicKey);

    signature = signer.sign(message);
    verify = verifier.verify(message, signature);

    expect(verify).toBe(true);

    // brainpoolP384
    keyPair = Helper.keyPair.generate.brainpoolP384();

    signer = Asymmetric.create.signer(keyPair.privateKey);
    verifier = Asymmetric.create.verifier(keyPair.publicKey);

    signature = signer.sign(message);
    verify = verifier.verify(message, signature);

    expect(verify).toBe(true);

    // sm2
    keyPair = Helper.keyPair.generate.sm2();

    signer = Asymmetric.create.signer(keyPair.privateKey);
    verifier = Asymmetric.create.verifier(keyPair.publicKey);

    signature = signer.sign(message);
    verify = verifier.verify(message, signature);

    expect(verify).toBe(true);
  });

  test('export keyPair(p256)', () => {
    let keyPair = Helper.keyPair.generate.p256();

    let signer = Asymmetric.create.signer(keyPair.privateKey);
    let signature = signer.sign(message);

    const exported = keyPair.publicKey.export({ type: 'spki', format: 'der' });

    const x = exported.subarray(-64, -32);
    const y = exported.subarray(-32);

    let compressedKey = x.toString('hex');

    if (parseInt(y.subarray(-1).toString('hex'), 16) % 2 === 0) {
      compressedKey = '02' + compressedKey;
    } else {
      compressedKey = '03' + compressedKey;
    }

    const uncompressed = crypto.ECDH.convertKey(compressedKey, CURVE.P256, 'hex', 'hex', 'uncompressed');

    const header = '3059301306072a8648ce3d020106082a8648ce3d030107034200';
    const key = Buffer.from(header + uncompressed, 'hex');

    const publicKey = Helper.keyPair.generate.publicKey({ type: 'spki', format: 'der', key: key });

    const verifier = Asymmetric.create.verifier(publicKey);
    const verify = verifier.verify(message, signature);

    expect(verify).toBe(true);
  });

  test('export keyPair(p384)', () => {
    let keyPair = Helper.keyPair.generate.p384();

    let signer = Asymmetric.create.signer(keyPair.privateKey);
    let signature = signer.sign(message);

    const exported = keyPair.publicKey.export({ type: 'spki', format: 'der' });

    const x = exported.subarray(-96, -48);
    const y = exported.subarray(-48);

    let compressedKey = x.toString('hex');

    if (parseInt(y.subarray(-1).toString('hex'), 16) % 2 === 0) {
      compressedKey = '02' + compressedKey;
    } else {
      compressedKey = '03' + compressedKey;
    }

    const uncompressed = crypto.ECDH.convertKey(compressedKey, CURVE.P384, 'hex', 'hex', 'uncompressed');

    const header = '3076301006072a8648ce3d020106052b81040022036200';
    const key = Buffer.from(header + uncompressed, 'hex');

    const publicKey = Helper.keyPair.generate.publicKey({ type: 'spki', format: 'der', key: key });

    const verifier = Asymmetric.create.verifier(publicKey);
    const verify = verifier.verify(message, signature);

    expect(verify).toBe(true);
  });

  test('export keyPair(brainpoolP256)', () => {
    let keyPair = Helper.keyPair.generate.brainpoolP256();

    let signer = Asymmetric.create.signer(keyPair.privateKey);
    let signature = signer.sign(message);

    const exported = keyPair.publicKey.export({ type: 'spki', format: 'der' });

    const x = exported.subarray(-64, -32);
    const y = exported.subarray(-32);

    let compressedKey = x.toString('hex');

    if (parseInt(y.subarray(-1).toString('hex'), 16) % 2 === 0) {
      compressedKey = '02' + compressedKey;
    } else {
      compressedKey = '03' + compressedKey;
    }

    const uncompressed = crypto.ECDH.convertKey(compressedKey, CURVE.BRAINPOOLP256R1, 'hex', 'hex', 'uncompressed');

    const header = '305a301406072a8648ce3d020106092b2403030208010107034200';
    const key = Buffer.from(header + uncompressed, 'hex');

    const publicKey = Helper.keyPair.generate.publicKey({ type: 'spki', format: 'der', key: key });

    const verifier = Asymmetric.create.verifier(publicKey);
    const verify = verifier.verify(message, signature);

    expect(verify).toBe(true);
  });

  test('export keyPair(brainpoolP384)', () => {
    let keyPair = Helper.keyPair.generate.brainpoolP384();

    let signer = Asymmetric.create.signer(keyPair.privateKey);
    let signature = signer.sign(message);

    const exported = keyPair.publicKey.export({ type: 'spki', format: 'der' });

    const x = exported.subarray(-96, -48);
    const y = exported.subarray(-48);

    let compressedKey = x.toString('hex');

    if (parseInt(y.subarray(-1).toString('hex'), 16) % 2 === 0) {
      compressedKey = '02' + compressedKey;
    } else {
      compressedKey = '03' + compressedKey;
    }

    const uncompressed = crypto.ECDH.convertKey(compressedKey, CURVE.BRAINPOOLP384R1, 'hex', 'hex', 'uncompressed');

    const header = '307a301406072a8648ce3d020106092b240303020801010b036200';
    const key = Buffer.from(header + uncompressed, 'hex');

    const publicKey = Helper.keyPair.generate.publicKey({ type: 'spki', format: 'der', key: key });

    const verifier = Asymmetric.create.verifier(publicKey);
    const verify = verifier.verify(message, signature);

    expect(verify).toBe(true);
  });

  test('signature(rsapss)', () => {
    const keyPair = Helper.keyPair.generate.rsapss({
      modulusLength: 256 * 8,
      hashAlgorithm: 'sha256',
    });

    let signer = Asymmetric.create.signer(keyPair.privateKey);
    let signature = signer.sign(message);

    const verifier = Asymmetric.create.verifier(keyPair.publicKey);
    const verify = verifier.verify(message, signature);

    expect(verify).toBe(true);
  });

  test('signature(dsa)', () => {
    const keyPair = Helper.keyPair.generate.dsa({
      modulusLength: 1024,
      divisorLength: 160,
    });

    let signer = Asymmetric.create.signer(keyPair.privateKey);
    let signature = signer.sign(message);

    const verifier = Asymmetric.create.verifier(keyPair.publicKey);
    const verify = verifier.verify(message, signature);

    expect(verify).toBe(true);
  });

  test('signature(ec)', () => {
    const keyPair = Helper.keyPair.generate.ec({ namedCurve: 'prime256v1' });

    let signer = Asymmetric.create.signer(keyPair.privateKey);
    let signature = signer.sign(message);

    const verifier = Asymmetric.create.verifier(keyPair.publicKey);
    const verify = verifier.verify(message, signature);

    expect(verify).toBe(true);
  });

  test('signature(ed25519)', () => {
    const keyPair = Helper.keyPair.generate.ed25519({ namedCurve: 'prime256v1' });

    let signer = Asymmetric.create.signer(keyPair.privateKey);
    let signature = signer.sign(message);

    const verifier = Asymmetric.create.verifier(keyPair.publicKey);
    const verify = verifier.verify(message, signature);

    expect(verify).toBe(true);
  });

  test('signature(ed448)', () => {
    const keyPair = Helper.keyPair.generate.ed448({ namedCurve: 'prime256v1' });

    let signer = Asymmetric.create.signer(keyPair.privateKey);
    let signature = signer.sign(message);

    const verifier = Asymmetric.create.verifier(keyPair.publicKey);
    const verify = verifier.verify(message, signature);

    expect(verify).toBe(true);
  });
});
