import { AEAD, Aead, HASH, Helper, PBKDF } from '../../src/index';

describe('Aead', () => {
  const passwordString = 'password';
  const passwordBuffer = Buffer.from(passwordString, 'utf8');

  const saltString = 'salt';
  const saltBuffer = Buffer.from(saltString, 'utf8');

  const keyString = 'key';
  const keyBuffer = Buffer.from(keyString, 'utf8');

  const nonceString = 'nonce';
  const nonceBuffer = Buffer.from(nonceString, 'utf8');

  const authTagLength = 12;
  const aad = Buffer.from('aad', 'utf8');

  const textString = 'Welcome to JihyunLab.';
  const textBuffer = Buffer.from(textString, 'utf8');

  test('hex()', () => {
    const values = Object.values(AEAD);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let key: string | Buffer = Helper.key.generate(name, passwordString, saltString);
      let aead = Aead.create(name, key);
      let nonce: string | Buffer;

      nonce = Helper.nonce.generate(name);

      let encrypted = aead.encrypt.hex(textString, nonce);
      let decrypted = aead.decrypt.hex(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toBe(textString);

      key = Helper.key.normalize(name, key);
      aead = Aead.create(name, key);

      decrypted = aead.decrypt.hex(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toBe(textString);

      key = Helper.key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, HASH.SHA256);
      aead = Aead.create(name, key, authTagLength);
      nonce = Helper.nonce.normalize(name, nonceString);

      encrypted = aead.encrypt.hex(textString, nonce);
      decrypted = aead.decrypt.hex(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toBe(textString);

      key = Helper.key.normalize(name, keyString);
      aead = Aead.create(name, key, authTagLength, aad);
      nonce = Helper.nonce.normalize(name, nonceBuffer);

      encrypted = aead.encrypt.hex(textString, nonce);

      key = Helper.key.normalize(name, keyBuffer);
      aead = Aead.create(name, key, authTagLength, aad);

      decrypted = aead.decrypt.hex(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toBe(textString);
    }
  });

  test('binary()', () => {
    const values = Object.values(AEAD);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let key: string | Buffer = Helper.key.generate(name, passwordString, saltString);
      let aead = Aead.create(name, key);
      let nonce: string | Buffer;

      nonce = Helper.nonce.generate(name);

      let encrypted = aead.encrypt.binary(textString, nonce);
      let decrypted = aead.decrypt.binary(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toBe(textString);

      key = Helper.key.normalize(name, key);
      aead = Aead.create(name, key);

      decrypted = aead.decrypt.binary(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toBe(textString);

      key = Helper.key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, HASH.SHA256);
      aead = Aead.create(name, key, authTagLength);
      nonce = Helper.nonce.normalize(name, nonceString);

      encrypted = aead.encrypt.binary(textString, nonce);
      decrypted = aead.decrypt.binary(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toBe(textString);

      key = Helper.key.normalize(name, keyString);
      aead = Aead.create(name, key, authTagLength, aad);
      nonce = Helper.nonce.normalize(name, nonceBuffer);

      encrypted = aead.encrypt.binary(textString, nonce);

      key = Helper.key.normalize(name, keyBuffer);
      aead = Aead.create(name, key, authTagLength, aad);

      decrypted = aead.decrypt.binary(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toBe(textString);
    }
  });

  test('base64()', () => {
    const values = Object.values(AEAD);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let key: string | Buffer = Helper.key.generate(name, passwordString, saltString);
      let aead = Aead.create(name, key);
      let nonce: string | Buffer;

      nonce = Helper.nonce.generate(name);

      let encrypted = aead.encrypt.base64(textString, nonce);
      let decrypted = aead.decrypt.base64(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toBe(textString);

      key = Helper.key.normalize(name, key);
      aead = Aead.create(name, key);

      decrypted = aead.decrypt.base64(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toBe(textString);

      key = Helper.key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, HASH.SHA256);
      aead = Aead.create(name, key, authTagLength);
      nonce = Helper.nonce.normalize(name, nonceString);

      encrypted = aead.encrypt.base64(textString, nonce);
      decrypted = aead.decrypt.base64(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toBe(textString);

      key = Helper.key.normalize(name, keyString);
      aead = Aead.create(name, key, authTagLength, aad);
      nonce = Helper.nonce.normalize(name, nonceBuffer);

      encrypted = aead.encrypt.base64(textString, nonce);

      key = Helper.key.normalize(name, keyBuffer);
      aead = Aead.create(name, key, authTagLength, aad);

      decrypted = aead.decrypt.base64(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toBe(textString);
    }
  });

  test('base64url()', () => {
    const values = Object.values(AEAD);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let key: string | Buffer = Helper.key.generate(name, passwordString, saltString);
      let aead = Aead.create(name, key);
      let nonce: string | Buffer;

      nonce = Helper.nonce.generate(name);

      let encrypted = aead.encrypt.base64url(textString, nonce);
      let decrypted = aead.decrypt.base64url(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toBe(textString);

      key = Helper.key.normalize(name, key);
      aead = Aead.create(name, key);

      decrypted = aead.decrypt.base64url(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toBe(textString);

      key = Helper.key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, HASH.SHA256);
      aead = Aead.create(name, key, authTagLength);
      nonce = Helper.nonce.normalize(name, nonceString);

      encrypted = aead.encrypt.base64url(textString, nonce);
      decrypted = aead.decrypt.base64url(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toBe(textString);

      key = Helper.key.normalize(name, keyString);
      aead = Aead.create(name, key, authTagLength, aad);
      nonce = Helper.nonce.normalize(name, nonceBuffer);

      encrypted = aead.encrypt.base64url(textString, nonce);

      key = Helper.key.normalize(name, keyBuffer);
      aead = Aead.create(name, key, authTagLength, aad);

      decrypted = aead.decrypt.base64url(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toBe(textString);
    }
  });

  test('string()', () => {
    const values = Object.values(AEAD);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let key: string | Buffer = Helper.key.generate(name, passwordString, saltString);
      let aead = Aead.create(name, key);
      let nonce: string | Buffer;

      nonce = Helper.nonce.generate(name);

      let encrypted = aead.encrypt.string(textString, nonce);
      let decrypted = aead.decrypt.string(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toBe(textString);

      key = Helper.key.normalize(name, key);
      aead = Aead.create(name, key);

      decrypted = aead.decrypt.string(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toBe(textString);

      key = Helper.key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, HASH.SHA256);
      aead = Aead.create(name, key, authTagLength);
      nonce = Helper.nonce.generate(name);

      encrypted = aead.encrypt.string(textString, nonce);
      decrypted = aead.decrypt.string(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toBe(textString);

      key = Helper.key.normalize(name, key);
      aead = Aead.create(name, key, authTagLength);

      decrypted = aead.decrypt.string(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toBe(textString);

      key = Helper.key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF);
      aead = Aead.create(name, key);
      nonce = Helper.nonce.normalize(name, nonceString);

      encrypted = aead.encrypt.string(textString, nonce);
      decrypted = aead.decrypt.string(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toBe(textString);

      const hashes = Object.values(HASH);

      for (let j = 0; j < hashes.length; j++) {
        key = Helper.key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, hashes[j]);
        aead = Aead.create(name, key);
        nonce = Helper.nonce.normalize(name, nonceBuffer);

        encrypted = aead.encrypt.string(textString, nonce);
        decrypted = aead.decrypt.string(encrypted.text, encrypted.tag, nonce);
        expect(decrypted).toBe(textString);
      }

      encrypted = aead.encrypt.string(textString, nonce, 'utf8', 'latin1');
      decrypted = aead.decrypt.string(encrypted.text, encrypted.tag, nonce, 'latin1', 'utf8');
      expect(decrypted).toBe(textString);
    }
  });

  test('buffer()', () => {
    const values = Object.values(AEAD);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let key: string | Buffer = Helper.key.generate(name, passwordString, saltString);
      let aead = Aead.create(name, key);
      let nonce: string | Buffer;

      nonce = Helper.nonce.generate(name);

      let encrypted = aead.encrypt.buffer(textBuffer, nonce);
      let decrypted = aead.decrypt.buffer(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Helper.key.normalize(name, key);
      aead = Aead.create(name, key);

      decrypted = aead.decrypt.buffer(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Helper.key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, HASH.SHA256);
      aead = Aead.create(name, key, authTagLength);
      nonce = Helper.nonce.generate(name);

      encrypted = aead.encrypt.buffer(textBuffer, nonce);
      decrypted = aead.decrypt.buffer(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Helper.key.normalize(name, key);
      aead = Aead.create(name, key, authTagLength);

      decrypted = aead.decrypt.buffer(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Helper.key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF);
      aead = Aead.create(name, key);
      nonce = Helper.nonce.normalize(name, nonceString);

      encrypted = aead.encrypt.buffer(textBuffer, nonce);
      decrypted = aead.decrypt.buffer(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toStrictEqual(textBuffer);

      const hashes = Object.values(HASH);

      for (let j = 0; j < hashes.length; j++) {
        key = Helper.key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, hashes[j]);
        aead = Aead.create(name, key);
        nonce = Helper.nonce.normalize(name, nonceBuffer);

        encrypted = aead.encrypt.buffer(textBuffer, nonce);
        decrypted = aead.decrypt.buffer(encrypted.text, encrypted.tag, nonce);
        expect(decrypted).toStrictEqual(textBuffer);
      }
    }
  });

  test('buffer(aes-gcm)', () => {
    const values = Object.values(AEAD);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      if (name !== AEAD.AES_128_GCM && name !== AEAD.AES_192_GCM && name !== AEAD.AES_256_GCM) {
        continue;
      }

      let key: string | Buffer = Helper.key.generate(name, passwordString, saltString);
      let aead = Aead.create(name, key, null);
      let nonce: string | Buffer;

      nonce = Helper.nonce.generate(name);

      let encrypted = aead.encrypt.buffer(textBuffer, nonce);
      let decrypted = aead.decrypt.buffer(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toStrictEqual(textBuffer);
    }
  });

  test('uint8Array()', () => {
    const values = Object.values(AEAD);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];

      let key: string | Buffer = Helper.key.generate(name, passwordString, saltString);
      let aead = Aead.create(name, key);
      let nonce: string | Buffer;

      nonce = Helper.nonce.generate(name);

      let encrypted = aead.encrypt.uint8Array(textBuffer, nonce);
      let decrypted = aead.decrypt.uint8Array(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Helper.key.normalize(name, key);
      aead = Aead.create(name, key);

      decrypted = aead.decrypt.uint8Array(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Helper.key.generate(name, passwordBuffer, saltBuffer, PBKDF.PBKDF2, 2048, HASH.SHA256);
      aead = Aead.create(name, key, authTagLength);
      nonce = Helper.nonce.normalize(name, nonceString);

      encrypted = aead.encrypt.uint8Array(textBuffer, nonce);
      decrypted = aead.decrypt.uint8Array(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Helper.key.normalize(name, keyString);
      aead = Aead.create(name, key, authTagLength, aad);
      nonce = Helper.nonce.normalize(name, nonceBuffer);

      encrypted = aead.encrypt.uint8Array(textBuffer, nonce);
      expect(decrypted).toStrictEqual(textBuffer);

      key = Helper.key.normalize(name, keyBuffer);
      aead = Aead.create(name, key, authTagLength, aad);

      decrypted = aead.decrypt.uint8Array(encrypted.text, encrypted.tag, nonce);
      expect(decrypted).toStrictEqual(textBuffer);
    }
  });

  test('example(basic)', () => {
    const key = Helper.key.generate(AEAD.AES_256_CCM, 'password', 'salt');
    const nonce = Helper.nonce.generate(AEAD.AES_256_CCM);

    const encrypted = Aead.create(AEAD.AES_256_CCM, key).encrypt.hex('string', nonce);
    const decrypted = Aead.create(AEAD.AES_256_CCM, key).decrypt.hex(encrypted.text, encrypted.tag, nonce);

    expect(decrypted).toBe('string');
  });

  test('example(buffer)', () => {
    const key = Helper.key.generate(AEAD.AES_256_CCM, 'password', 'salt');
    const nonce = Helper.nonce.generate(AEAD.AES_256_CCM);

    const encrypted = Aead.create(AEAD.AES_256_CCM, key).encrypt.buffer(Buffer.from('string'), nonce);
    const decrypted = Aead.create(AEAD.AES_256_CCM, key).decrypt.buffer(encrypted.text, encrypted.tag, nonce);

    expect(decrypted).toStrictEqual(Buffer.from('string'));
  });

  test('example(normalize)', () => {
    const key = Helper.key.normalize(AEAD.AES_256_CCM, Buffer.from('key'));
    const nonce = Helper.nonce.normalize(AEAD.AES_256_CCM, Buffer.from('nonce'));

    const encrypted = Aead.create(AEAD.AES_256_CCM, key).encrypt.buffer(Buffer.from('string'), nonce);
    const decrypted = Aead.create(AEAD.AES_256_CCM, key).decrypt.buffer(encrypted.text, encrypted.tag, nonce);

    expect(decrypted).toStrictEqual(Buffer.from('string'));
  });
});
