import { CRYPTO, Crypto } from '../src/index';

describe('Crypto', () => {
  const password = 'password';
  const passwordBuffer = Buffer.from('password', 'utf8');

  const salt = 'salt';
  const saltBuffer = Buffer.from('salt', 'utf8');

  const ivString = 'iv';
  const ivBuffer = Buffer.from('iv', 'utf8');

  const text = 'Welcome to JihyunLab.';
  const textBuffer = Buffer.from(text, 'utf8');

  test('hex', () => {
    const values = Object.values(CRYPTO);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let crypto = Crypto.create(name, password, salt);
      let iv = crypto.generateIv();

      let encrypted = crypto.encrypt.hex(text, iv);
      let decrypted = crypto.decrypt.hex(encrypted, iv);
      expect(decrypted).toBe(text);

      crypto = Crypto.create(name, password, salt);

      decrypted = crypto.decrypt.hex(encrypted, iv);
      expect(decrypted).toBe(text);

      crypto = Crypto.create(name, passwordBuffer, saltBuffer);
      iv = crypto.generateIv(ivString);

      encrypted = crypto.encrypt.hex(text, iv);
      decrypted = crypto.decrypt.hex(encrypted, iv);
      expect(decrypted).toBe(text);

      crypto = Crypto.create(name, passwordBuffer, saltBuffer);
      iv = crypto.generateIv(ivBuffer);

      encrypted = crypto.encrypt.hex(text, iv);
      decrypted = crypto.decrypt.hex(encrypted, iv);
      expect(decrypted).toBe(text);
    }
  });

  test('binary', () => {
    const values = Object.values(CRYPTO);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let crypto = Crypto.create(name, password, salt);
      let iv = crypto.generateIv();

      let encrypted = crypto.encrypt.binary(text, iv);
      let decrypted = crypto.decrypt.binary(encrypted, iv);
      expect(decrypted).toBe(text);

      crypto = Crypto.create(name, password, salt);

      decrypted = crypto.decrypt.binary(encrypted, iv);
      expect(decrypted).toBe(text);

      crypto = Crypto.create(name, passwordBuffer, saltBuffer);
      iv = crypto.generateIv(ivString);

      encrypted = crypto.encrypt.binary(text, iv);
      decrypted = crypto.decrypt.binary(encrypted, iv);
      expect(decrypted).toBe(text);

      crypto = Crypto.create(name, passwordBuffer, saltBuffer);
      iv = crypto.generateIv(ivBuffer);

      encrypted = crypto.encrypt.binary(text, iv);
      decrypted = crypto.decrypt.binary(encrypted, iv);
      expect(decrypted).toBe(text);
    }
  });

  test('base64', () => {
    const values = Object.values(CRYPTO);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let crypto = Crypto.create(name, password, salt);
      let iv = crypto.generateIv();

      let encrypted = crypto.encrypt.base64(text, iv);
      let decrypted = crypto.decrypt.base64(encrypted, iv);
      expect(decrypted).toBe(text);

      crypto = Crypto.create(name, password, salt);

      decrypted = crypto.decrypt.base64(encrypted, iv);
      expect(decrypted).toBe(text);

      crypto = Crypto.create(name, passwordBuffer, saltBuffer);
      iv = crypto.generateIv(ivString);

      encrypted = crypto.encrypt.base64(text, iv);
      decrypted = crypto.decrypt.base64(encrypted, iv);
      expect(decrypted).toBe(text);

      crypto = Crypto.create(name, passwordBuffer, saltBuffer);
      iv = crypto.generateIv(ivBuffer);

      encrypted = crypto.encrypt.base64(text, iv);
      decrypted = crypto.decrypt.base64(encrypted, iv);
      expect(decrypted).toBe(text);
    }
  });

  test('string', () => {
    const values = Object.values(CRYPTO);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let crypto = Crypto.create(name, password, salt);
      let iv = crypto.generateIv();

      let encrypted = crypto.encrypt.string(text, iv);
      let decrypted = crypto.decrypt.string(encrypted, iv);
      expect(decrypted).toBe(text);

      crypto = Crypto.create(name, password, salt);

      decrypted = crypto.decrypt.string(encrypted, iv);
      expect(decrypted).toBe(text);

      crypto = Crypto.create(name, passwordBuffer, saltBuffer);
      iv = crypto.generateIv(ivString);

      encrypted = crypto.encrypt.string(text, iv);
      decrypted = crypto.decrypt.string(encrypted, iv);
      expect(decrypted).toBe(text);

      crypto = Crypto.create(name, passwordBuffer, saltBuffer);
      iv = crypto.generateIv(ivBuffer);

      encrypted = crypto.encrypt.string(text, iv);
      decrypted = crypto.decrypt.string(encrypted, iv);
      expect(decrypted).toBe(text);

      encrypted = crypto.encrypt.string(text, iv, 'utf8', 'latin1');
      decrypted = crypto.decrypt.string(encrypted, iv, 'latin1', 'utf8');
      expect(decrypted).toBe(text);
    }
  });

  test('buffer', () => {
    const values = Object.values(CRYPTO);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let crypto = Crypto.create(name, password, salt);
      let iv = crypto.generateIv();

      let encrypted = crypto.encrypt.buffer(textBuffer, iv);
      let decrypted = crypto.decrypt.buffer(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      crypto = Crypto.create(name, password, salt);

      decrypted = crypto.decrypt.buffer(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      crypto = Crypto.create(name, passwordBuffer, saltBuffer);
      iv = crypto.generateIv(ivString);

      encrypted = crypto.encrypt.buffer(textBuffer, iv);
      decrypted = crypto.decrypt.buffer(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      crypto = Crypto.create(name, passwordBuffer, saltBuffer);
      iv = crypto.generateIv(ivBuffer);

      encrypted = crypto.encrypt.buffer(textBuffer, iv);
      decrypted = crypto.decrypt.buffer(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);
    }
  });

  test('uint8Array', () => {
    const values = Object.values(CRYPTO);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let crypto = Crypto.create(name, password, salt);
      let iv = crypto.generateIv();

      let encrypted = crypto.encrypt.uint8Array(textBuffer, iv);
      let decrypted = crypto.decrypt.uint8Array(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      crypto = Crypto.create(name, password, salt);

      decrypted = crypto.decrypt.uint8Array(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      crypto = Crypto.create(name, passwordBuffer, saltBuffer);
      iv = crypto.generateIv(ivString);

      encrypted = crypto.encrypt.uint8Array(textBuffer, iv);
      decrypted = crypto.decrypt.uint8Array(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);

      crypto = Crypto.create(name, passwordBuffer, saltBuffer);
      iv = crypto.generateIv(ivBuffer);

      encrypted = crypto.encrypt.uint8Array(textBuffer, iv);
      decrypted = crypto.decrypt.uint8Array(encrypted, iv);
      expect(decrypted).toStrictEqual(textBuffer);
    }
  });
});
