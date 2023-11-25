import { CRYPTO, Crypto, HASH, Iv, Key, PBKDF } from '../src/index';

describe('Crypto', () => {
  const passwordString = 'password';
  const passwordBuffer = Buffer.from(passwordString, 'utf8');

  const saltString = 'salt';
  const saltBuffer = Buffer.from(saltString, 'utf8');

  const keyString = 'key';
  const keyBuffer = Buffer.from(keyString, 'utf8');

  const ivString = 'iv';
  const ivBuffer = Buffer.from(ivString, 'utf8');

  const textString = 'Welcome to JihyunLab.';
  const textBuffer = Buffer.from(textString, 'utf8');

  test('hex', () => {
    const values = Object.values(CRYPTO);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let key: string | Buffer = Key.generate(name, passwordString, saltString);
      let crypto = Crypto.create(name, key);
      let iv: string | Buffer | null;

      iv = Iv.generate(name);

      let encrypted = crypto.encrypt.hex(textString, iv);
      let decrypted = crypto.decrypt.hex(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Key.normalize(name, key);
      crypto = Crypto.create(name, key);

      decrypted = crypto.decrypt.hex(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, HASH.SHA_256);
      crypto = Crypto.create(name, key);
      iv = Iv.normalize(name, ivString);

      encrypted = crypto.encrypt.hex(textString, iv);
      decrypted = crypto.decrypt.hex(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Key.normalize(name, keyString);
      crypto = Crypto.create(name, key);
      iv = Iv.normalize(name, ivBuffer);

      encrypted = crypto.encrypt.hex(textString, iv);

      key = Key.normalize(name, keyBuffer);
      crypto = Crypto.create(name, key);

      decrypted = crypto.decrypt.hex(encrypted, iv);
      expect(decrypted).toBe(textString);
    }
  });

  test('binary', () => {
    const values = Object.values(CRYPTO);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let key: string | Buffer = Key.generate(name, passwordString, saltString);
      let crypto = Crypto.create(name, key);
      let iv: string | Buffer | null;

      iv = Iv.generate(name);

      let encrypted = crypto.encrypt.binary(textString, iv);
      let decrypted = crypto.decrypt.binary(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Key.normalize(name, key);
      crypto = Crypto.create(name, key);

      decrypted = crypto.decrypt.binary(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, HASH.SHA_256);
      crypto = Crypto.create(name, key);
      iv = Iv.normalize(name, ivString);

      encrypted = crypto.encrypt.binary(textString, iv);
      decrypted = crypto.decrypt.binary(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Key.normalize(name, keyString);
      crypto = Crypto.create(name, key);
      iv = Iv.normalize(name, ivBuffer);

      encrypted = crypto.encrypt.binary(textString, iv);

      key = Key.normalize(name, keyBuffer);
      crypto = Crypto.create(name, key);

      decrypted = crypto.decrypt.binary(encrypted, iv);
      expect(decrypted).toBe(textString);
    }
  });

  test('base64', () => {
    const values = Object.values(CRYPTO);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let key: string | Buffer = Key.generate(name, passwordString, saltString);
      let crypto = Crypto.create(name, key);
      let iv: string | Buffer | null;

      iv = Iv.generate(name);

      let encrypted = crypto.encrypt.base64(textString, iv);
      let decrypted = crypto.decrypt.base64(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Key.normalize(name, key);
      crypto = Crypto.create(name, key);

      decrypted = crypto.decrypt.base64(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, HASH.SHA_256);
      crypto = Crypto.create(name, key);
      iv = Iv.normalize(name, ivString);

      encrypted = crypto.encrypt.base64(textString, iv);
      decrypted = crypto.decrypt.base64(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Key.normalize(name, keyString);
      crypto = Crypto.create(name, key);
      iv = Iv.normalize(name, ivBuffer);

      encrypted = crypto.encrypt.base64(textString, iv);

      key = Key.normalize(name, keyBuffer);
      crypto = Crypto.create(name, key);

      decrypted = crypto.decrypt.base64(encrypted, iv);
      expect(decrypted).toBe(textString);
    }
  });

  test('string', () => {
    const values = Object.values(CRYPTO);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let key: string | Buffer = Key.generate(name, passwordString, saltString);
      let crypto = Crypto.create(name, key);
      let iv: string | Buffer | null;

      iv = Iv.generate(name);

      let encrypted = crypto.encrypt.string(textString, iv);
      let decrypted = crypto.decrypt.string(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Key.normalize(name, key);
      crypto = Crypto.create(name, key);

      decrypted = crypto.decrypt.string(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, HASH.SHA_256);
      crypto = Crypto.create(name, key);
      iv = Iv.generate(name);

      encrypted = crypto.encrypt.string(textString, iv);
      decrypted = crypto.decrypt.string(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Key.normalize(name, key);
      crypto = Crypto.create(name, key);

      decrypted = crypto.decrypt.string(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF);
      crypto = Crypto.create(name, key);
      iv = Iv.normalize(name, ivString);

      encrypted = crypto.encrypt.string(textString, iv);
      decrypted = crypto.decrypt.string(encrypted, iv);
      expect(decrypted).toBe(textString);

      const hashes = Object.values(HASH);

      for (let j = 0; j < hashes.length; j++) {
        key = Key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, hashes[j]);
        crypto = Crypto.create(name, key);
        iv = Iv.normalize(name, ivBuffer);

        encrypted = crypto.encrypt.string(textString, iv);
        decrypted = crypto.decrypt.string(encrypted, iv);
        expect(decrypted).toBe(textString);
      }

      encrypted = crypto.encrypt.string(textString, iv, 'utf8', 'latin1');
      decrypted = crypto.decrypt.string(encrypted, iv, 'latin1', 'utf8');
      expect(decrypted).toBe(textString);
    }
  });

  test('buffer', () => {
    const values = Object.values(CRYPTO);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let key: string | Buffer = Key.generate(name, passwordString, saltString);
      let crypto = Crypto.create(name, key);
      let iv: string | Buffer | null;

      iv = Iv.generate(name);

      let encrypted = crypto.encrypt.buffer(textBuffer, iv);
      let decrypted = crypto.decrypt.buffer(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Key.normalize(name, key);
      crypto = Crypto.create(name, key);

      decrypted = crypto.decrypt.buffer(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, HASH.SHA_256);
      crypto = Crypto.create(name, key);
      iv = Iv.generate(name);

      encrypted = crypto.encrypt.buffer(textBuffer, iv);
      decrypted = crypto.decrypt.buffer(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Key.normalize(name, key);
      crypto = Crypto.create(name, key);

      decrypted = crypto.decrypt.buffer(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF);
      crypto = Crypto.create(name, key);
      iv = Iv.normalize(name, ivString);

      encrypted = crypto.encrypt.buffer(textBuffer, iv);
      decrypted = crypto.decrypt.buffer(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      const hashes = Object.values(HASH);

      for (let j = 0; j < hashes.length; j++) {
        key = Key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, hashes[j]);
        crypto = Crypto.create(name, key);
        iv = Iv.normalize(name, ivBuffer);

        encrypted = crypto.encrypt.buffer(textBuffer, iv);
        decrypted = crypto.decrypt.buffer(encrypted, iv);
        expect(decrypted).toStrictEqual(textBuffer);
      }
    }
  });

  test('uint8Array', () => {
    const values = Object.values(CRYPTO);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let key: string | Buffer = Key.generate(name, passwordString, saltString);
      let crypto = Crypto.create(name, key);
      let iv: string | Buffer | null;

      iv = Iv.generate(name);

      let encrypted = crypto.encrypt.uint8Array(textBuffer, iv);
      let decrypted = crypto.decrypt.uint8Array(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Key.normalize(name, key);
      crypto = Crypto.create(name, key);

      decrypted = crypto.decrypt.uint8Array(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, HASH.SHA_256);
      crypto = Crypto.create(name, key);
      iv = Iv.normalize(name, ivString);

      encrypted = crypto.encrypt.uint8Array(textBuffer, iv);
      decrypted = crypto.decrypt.uint8Array(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Key.normalize(name, keyString);
      crypto = Crypto.create(name, key);
      iv = Iv.normalize(name, ivBuffer);

      encrypted = crypto.encrypt.uint8Array(textBuffer, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Key.normalize(name, keyBuffer);
      crypto = Crypto.create(name, key);

      decrypted = crypto.decrypt.uint8Array(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);
    }
  });

  test('example(basic)', () => {
    const key = Key.generate(CRYPTO.AES_256_CBC, 'password', 'salt');
    const iv = Iv.generate(CRYPTO.AES_256_CBC);

    const encrypted = Crypto.create(CRYPTO.AES_256_CBC, key).encrypt.hex('string', iv);
    const decrypted = Crypto.create(CRYPTO.AES_256_CBC, key).decrypt.hex(encrypted, iv);

    expect(decrypted).toBe('string');
  });

  test('example(buffer)', () => {
    const key = Key.generate(CRYPTO.AES_256_CBC, Buffer.from('password'), Buffer.from('salt'));
    const iv = Iv.generate(CRYPTO.AES_256_CBC);

    const encrypted = Crypto.create(CRYPTO.AES_256_CBC, key).encrypt.buffer(Buffer.from('string'), iv);
    const decrypted = Crypto.create(CRYPTO.AES_256_CBC, key).decrypt.buffer(encrypted, iv);

    expect(decrypted).toStrictEqual(Buffer.from('string'));
  });

  test('example(custom)', () => {
    const key = Key.generate(CRYPTO.AES_256_CBC, 'password', 'salt');
    const iv = Iv.generate(CRYPTO.AES_256_CBC);

    const encrypted = Crypto.create(CRYPTO.AES_256_CBC, key).encrypt.string('string', iv, 'utf8', 'hex');
    const decrypted = Crypto.create(CRYPTO.AES_256_CBC, key).decrypt.string(encrypted, iv, 'hex', 'utf8');

    expect(decrypted).toStrictEqual('string');
  });
});
