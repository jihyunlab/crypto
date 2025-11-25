/**
 * @jest-environment node
 */
import {
  HASH,
  createHash,
  CIPHER,
  createCipher,
  CRYPTO,
  createCrypto,
  JwtHelper,
} from '../src/index';

describe('Crypto', () => {
  test(`Positive: HASH.SHA_256`, async () => {
    const hash = await createHash(HASH.SHA_256);
    const hashed = await hash.digest(
      new Uint8Array(Buffer.from('jihyunlab', 'utf8'))
    );

    expect(Buffer.from(hashed).toString('hex')).toBe(
      'c86f2dd19d3a3ff4f1c890a520f30a9165cc2cb3e23f39d0b95d65007ac65264'
    );
  });

  test(`Positive: HASH.SHA_256 - uint8array`, async () => {
    const hash = await createHash(HASH.SHA_256);
    const hashed = await hash.digest(
      new Uint8Array([106, 105, 104, 121, 117, 110, 108, 97, 98])
    );

    expect(hashed).toStrictEqual(
      new Uint8Array([
        200, 111, 45, 209, 157, 58, 63, 244, 241, 200, 144, 165, 32, 243, 10,
        145, 101, 204, 44, 179, 226, 63, 57, 208, 185, 93, 101, 0, 122, 198, 82,
        100,
      ])
    );
  });

  test(`Positive: HASH.SHA_384`, async () => {
    const hash = await createHash(HASH.SHA_384);
    const hashed = await hash.digest(
      new Uint8Array(Buffer.from('jihyunlab', 'utf8'))
    );

    expect(Buffer.from(hashed).toString('hex')).toStrictEqual(
      'fafc0d25d3b79037e396608db8a27d1cfb7280da4dc51874b518c20073b890016aa89c8b6b17531b161538c3d8467970'
    );
  });

  test(`Positive: CIPHER.AES_256_CBC`, async () => {
    let cipher = await createCipher(CIPHER.AES_256_CBC, 'key');

    const encrypted = await cipher.encrypt('value');

    cipher = await createCipher(CIPHER.AES_256_CBC, 'key');

    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(new Uint8Array([118, 97, 108, 117, 101]));
  });

  test(`Positive: CIPHER.AES_256_CBC - options`, async () => {
    let cipher = await createCipher(CIPHER.AES_256_CBC, 'key', {
      salt: 'salt',
      iterations: 128,
      ivLength: 16,
    });

    const encrypted = await cipher.encrypt('value');

    cipher = await createCipher(CIPHER.AES_256_CBC, 'key', {
      salt: 'salt',
      iterations: 128,
      ivLength: 16,
    });
    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(new Uint8Array([118, 97, 108, 117, 101]));
  });

  test(`Positive: CIPHER.AES_256_CBC - uint8array`, async () => {
    let cipher = await createCipher(CIPHER.AES_256_CBC, 'key');

    const encrypted = await cipher.encrypt(new Uint8Array([10, 20, 30, 40]));

    cipher = await createCipher(CIPHER.AES_256_CBC, 'key');

    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(new Uint8Array([10, 20, 30, 40]));
  });

  test(`Positive: CIPHER.AES_256_CBC - from web crypto`, async () => {
    const encrypted =
      '66da95a860f8f040cd64460bc1bf47a4673c99ffd2858e9ca997264475bf0f4a';

    const cipher = await createCipher(CIPHER.AES_256_CBC, 'key');
    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(new Uint8Array([118, 97, 108, 117, 101]));
  });

  test(`Positive: CIPHER.AES_256_CBC - uint8array - from web crypto`, async () => {
    const encrypted = new Uint8Array([
      202, 231, 157, 158, 39, 166, 225, 229, 57, 46, 25, 186, 1, 50, 33, 187,
      204, 255, 138, 182, 92, 166, 83, 189, 181, 228, 109, 28, 123, 93, 164, 58,
    ]);

    const cipher = await createCipher(CIPHER.AES_256_CBC, 'key');
    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(new Uint8Array([10, 20, 30, 40]));
  });

  test(`Positive: CIPHER.AES_256_CBC - from web-secure-storage`, async () => {
    const encrypted =
      'e36e4673703230dd1f7e8e2083a934760a6ca0e542a2f7ab9a61ee439601a983bcaacf2e75fb7343914ec30d41b44db4';

    const cipher = await createCipher(CIPHER.AES_256_CBC, 'key');
    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(
      new Uint8Array([
        119, 101, 98, 45, 115, 101, 99, 117, 114, 101, 45, 115, 116, 111, 114,
        97, 103, 101,
      ])
    );
  });

  test(`Positive: CIPHER.AES_256_GCM`, async () => {
    let cipher = await createCipher(CIPHER.AES_256_GCM, 'key');

    const encrypted = await cipher.encrypt('value');

    cipher = await createCipher(CIPHER.AES_256_GCM, 'key');

    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(new Uint8Array([118, 97, 108, 117, 101]));
  });

  test(`Positive: CIPHER.AES_256_GCM - options`, async () => {
    let cipher = await createCipher(CIPHER.AES_256_GCM, 'key', {
      salt: 'salt',
      iterations: 128,
      ivLength: 12,
      tagLength: 128,
      additionalData: new Uint8Array([1, 2, 3, 4]),
    });

    const encrypted = await cipher.encrypt('value');

    cipher = await createCipher(CIPHER.AES_256_GCM, 'key', {
      salt: 'salt',
      additionalData: new Uint8Array([1, 2, 3, 4]),
    });

    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(new Uint8Array([118, 97, 108, 117, 101]));
  });

  test(`Positive: CIPHER.AES_256_GCM - uint8array`, async () => {
    let cipher = await createCipher(CIPHER.AES_256_GCM, 'key');

    const encrypted = await cipher.encrypt(new Uint8Array([10, 20, 30, 40]));

    cipher = await createCipher(CIPHER.AES_256_GCM, 'key');

    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(new Uint8Array([10, 20, 30, 40]));
  });

  test(`Positive: CIPHER.AES_256_GCM - from web crypto`, async () => {
    const encrypted =
      '88c296965810c596c10fdf2d7bfcd98bc6faf33aa275c3ffa5ea6e9c91e88c884f';

    const cipher = await createCipher(CIPHER.AES_256_GCM, 'key');
    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(new Uint8Array([118, 97, 108, 117, 101]));
  });

  test(`Positive: CIPHER.AES_256_GCM - uint8array - from web crypto`, async () => {
    const encrypted = new Uint8Array([
      22, 27, 221, 115, 233, 78, 143, 23, 177, 145, 47, 8, 67, 217, 208, 190,
      29, 206, 58, 17, 22, 191, 2, 153, 93, 226, 220, 39, 106, 250, 1, 87,
    ]);

    const cipher = await createCipher(CIPHER.AES_256_GCM, 'key');
    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(new Uint8Array([10, 20, 30, 40]));
  });

  test(`Positive: CIPHER.AES_256_GCM - from web-secure-storage`, async () => {
    const encrypted =
      '5751cc2e9ddeb49c8ba5ed58b7b73a4129606a4249022df3c223ca2ed74557dbbc6f14e82935640dc52b3a70e9c6';

    const cipher = await createCipher(CIPHER.AES_256_GCM, 'key');
    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(
      new Uint8Array([
        119, 101, 98, 45, 115, 101, 99, 117, 114, 101, 45, 115, 116, 111, 114,
        97, 103, 101,
      ])
    );
  });

  test(`Positive: CRYPTO.RSA_SHA384`, async () => {
    let crypto = await createCrypto(CRYPTO.RSA_SHA384);

    const keyPair = await crypto.generateKeyPair();
    const privateKey = await crypto.createPrivateKeyFromPem(keyPair.privateKey);

    const toBeSigned = await JwtHelper.createToBeSigned(
      { alg: 'RS384', typ: 'JWT' },
      { name: 'JihyunLab' }
    );

    const jwt = await JwtHelper.createJwt(
      toBeSigned,
      await crypto.sign(privateKey, toBeSigned)
    );

    crypto = await createCrypto(CRYPTO.RSA_SHA384, {
      modulusLength: 4096,
      use: 'sig',
    });

    let publicKey = await crypto.createPublicKeyFromPem(keyPair.publicKey);

    const parsed = await JwtHelper.parseJwt(jwt);

    let verified = await crypto.verify(
      publicKey,
      parsed.toBeSigned,
      parsed.signature
    );

    expect(verified).toBe(true);

    const jwk = await crypto.createJwk('kid', privateKey);

    publicKey = await crypto.createPublicKeyFromJwk(jwk);

    verified = await crypto.verify(
      publicKey,
      parsed.toBeSigned,
      parsed.signature
    );

    expect(verified).toBe(true);
  });
});
