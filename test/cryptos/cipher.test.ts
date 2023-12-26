import { CIPHER, Cipher, HASH, Helper, PBKDF } from '../../src/index';

describe('Cipher', () => {
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
    const values = Object.values(CIPHER);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let key: string | Buffer = Helper.key.generate(name, passwordString, saltString);
      let crypto = Cipher.create(name, key);
      let iv: string | Buffer | null;

      iv = Helper.iv.generate(name);

      let encrypted = crypto.encrypt.hex(textString, iv);
      let decrypted = crypto.decrypt.hex(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Helper.key.normalize(name, key);
      crypto = Cipher.create(name, key);

      decrypted = crypto.decrypt.hex(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Helper.key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, HASH.SHA256);
      crypto = Cipher.create(name, key);
      iv = Helper.iv.normalize(name, ivString);

      encrypted = crypto.encrypt.hex(textString, iv);
      decrypted = crypto.decrypt.hex(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Helper.key.normalize(name, keyString);
      crypto = Cipher.create(name, key);
      iv = Helper.iv.normalize(name, ivBuffer);

      encrypted = crypto.encrypt.hex(textString, iv);

      key = Helper.key.normalize(name, keyBuffer);
      crypto = Cipher.create(name, key);

      decrypted = crypto.decrypt.hex(encrypted, iv);
      expect(decrypted).toBe(textString);
    }
  });

  test('binary', () => {
    const values = Object.values(CIPHER);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let key: string | Buffer = Helper.key.generate(name, passwordString, saltString);
      let crypto = Cipher.create(name, key);
      let iv: string | Buffer | null;

      iv = Helper.iv.generate(name);

      let encrypted = crypto.encrypt.binary(textString, iv);
      let decrypted = crypto.decrypt.binary(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Helper.key.normalize(name, key);
      crypto = Cipher.create(name, key);

      decrypted = crypto.decrypt.binary(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Helper.key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, HASH.SHA256);
      crypto = Cipher.create(name, key);
      iv = Helper.iv.normalize(name, ivString);

      encrypted = crypto.encrypt.binary(textString, iv);
      decrypted = crypto.decrypt.binary(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Helper.key.normalize(name, keyString);
      crypto = Cipher.create(name, key);
      iv = Helper.iv.normalize(name, ivBuffer);

      encrypted = crypto.encrypt.binary(textString, iv);

      key = Helper.key.normalize(name, keyBuffer);
      crypto = Cipher.create(name, key);

      decrypted = crypto.decrypt.binary(encrypted, iv);
      expect(decrypted).toBe(textString);
    }
  });

  test('base64', () => {
    const values = Object.values(CIPHER);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let key: string | Buffer = Helper.key.generate(name, passwordString, saltString);
      let crypto = Cipher.create(name, key);
      let iv: string | Buffer | null;

      iv = Helper.iv.generate(name);

      let encrypted = crypto.encrypt.base64(textString, iv);
      let decrypted = crypto.decrypt.base64(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Helper.key.normalize(name, key);
      crypto = Cipher.create(name, key);

      decrypted = crypto.decrypt.base64(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Helper.key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, HASH.SHA256);
      crypto = Cipher.create(name, key);
      iv = Helper.iv.normalize(name, ivString);

      encrypted = crypto.encrypt.base64(textString, iv);
      decrypted = crypto.decrypt.base64(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Helper.key.normalize(name, keyString);
      crypto = Cipher.create(name, key);
      iv = Helper.iv.normalize(name, ivBuffer);

      encrypted = crypto.encrypt.base64(textString, iv);

      key = Helper.key.normalize(name, keyBuffer);
      crypto = Cipher.create(name, key);

      decrypted = crypto.decrypt.base64(encrypted, iv);
      expect(decrypted).toBe(textString);
    }
  });

  test('string', () => {
    const values = Object.values(CIPHER);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let key: string | Buffer = Helper.key.generate(name, passwordString, saltString);
      let crypto = Cipher.create(name, key);
      let iv: string | Buffer | null;

      iv = Helper.iv.generate(name);

      let encrypted = crypto.encrypt.string(textString, iv);
      let decrypted = crypto.decrypt.string(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Helper.key.normalize(name, key);
      crypto = Cipher.create(name, key);

      decrypted = crypto.decrypt.string(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Helper.key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, HASH.SHA256);
      crypto = Cipher.create(name, key);
      iv = Helper.iv.generate(name);

      encrypted = crypto.encrypt.string(textString, iv);
      decrypted = crypto.decrypt.string(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Helper.key.normalize(name, key);
      crypto = Cipher.create(name, key);

      decrypted = crypto.decrypt.string(encrypted, iv);
      expect(decrypted).toBe(textString);

      key = Helper.key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF);
      crypto = Cipher.create(name, key);
      iv = Helper.iv.normalize(name, ivString);

      encrypted = crypto.encrypt.string(textString, iv);
      decrypted = crypto.decrypt.string(encrypted, iv);
      expect(decrypted).toBe(textString);

      const hashes = Object.values(HASH);

      for (let j = 0; j < hashes.length; j++) {
        key = Helper.key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, hashes[j]);
        crypto = Cipher.create(name, key);
        iv = Helper.iv.normalize(name, ivBuffer);

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
    const values = Object.values(CIPHER);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let key: string | Buffer = Helper.key.generate(name, passwordString, saltString);
      let crypto = Cipher.create(name, key);
      let iv: string | Buffer | null;

      iv = Helper.iv.generate(name);

      let encrypted = crypto.encrypt.buffer(textBuffer, iv);
      let decrypted = crypto.decrypt.buffer(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Helper.key.normalize(name, key);
      crypto = Cipher.create(name, key);

      decrypted = crypto.decrypt.buffer(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Helper.key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, HASH.SHA256);
      crypto = Cipher.create(name, key);
      iv = Helper.iv.generate(name);

      encrypted = crypto.encrypt.buffer(textBuffer, iv);
      decrypted = crypto.decrypt.buffer(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Helper.key.normalize(name, key);
      crypto = Cipher.create(name, key);

      decrypted = crypto.decrypt.buffer(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Helper.key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF);
      crypto = Cipher.create(name, key);
      iv = Helper.iv.normalize(name, ivString);

      encrypted = crypto.encrypt.buffer(textBuffer, iv);
      decrypted = crypto.decrypt.buffer(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      const hashes = Object.values(HASH);

      for (let j = 0; j < hashes.length; j++) {
        key = Helper.key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, hashes[j]);
        crypto = Cipher.create(name, key);
        iv = Helper.iv.normalize(name, ivBuffer);

        encrypted = crypto.encrypt.buffer(textBuffer, iv);
        decrypted = crypto.decrypt.buffer(encrypted, iv);
        expect(decrypted).toStrictEqual(textBuffer);
      }
    }
  });

  test('uint8Array', () => {
    const values = Object.values(CIPHER);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let key: string | Buffer = Helper.key.generate(name, passwordString, saltString);
      let crypto = Cipher.create(name, key);
      let iv: string | Buffer | null;

      iv = Helper.iv.generate(name);

      let encrypted = crypto.encrypt.uint8Array(textBuffer, iv);
      let decrypted = crypto.decrypt.uint8Array(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Helper.key.normalize(name, key);
      crypto = Cipher.create(name, key);

      decrypted = crypto.decrypt.uint8Array(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Helper.key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, HASH.SHA256);
      crypto = Cipher.create(name, key);
      iv = Helper.iv.normalize(name, ivString);

      encrypted = crypto.encrypt.uint8Array(textBuffer, iv);
      decrypted = crypto.decrypt.uint8Array(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Helper.key.normalize(name, keyString);
      crypto = Cipher.create(name, key);
      iv = Helper.iv.normalize(name, ivBuffer);

      encrypted = crypto.encrypt.uint8Array(textBuffer, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Helper.key.normalize(name, keyBuffer);
      crypto = Cipher.create(name, key);

      decrypted = crypto.decrypt.uint8Array(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);
    }
  });

  test('example(basic)', () => {
    const key = Helper.key.generate(CIPHER.AES_256_CBC, 'password', 'salt');
    const iv = Helper.iv.generate(CIPHER.AES_256_CBC);

    const encrypted = Cipher.create(CIPHER.AES_256_CBC, key).encrypt.hex('string', iv);
    const decrypted = Cipher.create(CIPHER.AES_256_CBC, key).decrypt.hex(encrypted, iv);

    expect(decrypted).toBe('string');
  });

  test('example(buffer)', () => {
    const key = Helper.key.generate(CIPHER.AES_256_CBC, Buffer.from('password'), Buffer.from('salt'));
    const iv = Helper.iv.generate(CIPHER.AES_256_CBC);

    const encrypted = Cipher.create(CIPHER.AES_256_CBC, key).encrypt.buffer(Buffer.from('string'), iv);
    const decrypted = Cipher.create(CIPHER.AES_256_CBC, key).decrypt.buffer(encrypted, iv);

    expect(decrypted).toStrictEqual(Buffer.from('string'));
  });

  test('example(custom)', () => {
    const key = Helper.key.generate('sm4-cbc', 'password', 'salt');
    const iv = Helper.iv.generate('sm4-cbc');

    const encrypted = Cipher.create('sm4-cbc', key).encrypt.string('string', iv, 'utf8', 'base64url');
    const decrypted = Cipher.create('sm4-cbc', key).decrypt.string(encrypted, iv, 'base64url', 'utf8');

    expect(decrypted).toStrictEqual('string');
  });
});
