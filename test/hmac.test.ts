import { HMAC, Hmac } from '../src/index';

describe('Hmac', () => {
  const keyString = 'key';
  const keyBuffer = Buffer.from(keyString, 'utf8');

  const textString = 'jihyunlab';
  const textBuffer = Buffer.from(textString, 'utf8');

  const map = new Map([
    ['MD5', 'b83f3c02a9c1d1eef2832a72ff5d4dce'],
    ['SHA1', '90ae9c4aaa8a10b9b71818a7a34f98bc4b922f51'],
    ['SHA-224', '8010fcc2a4fc50411ccf4a7a26ea5e436b31b6287aa5c68716262446'],
    ['SHA-256', 'd9febb302acb21d23b3efb78ebcd0d60d23e3f7e7c911f15dc7c04430a0cbb2c'],
    ['SHA-384', '7404fccec10a65fb1f25e71d9e43eab937a1d23efcf7d052947bce8783611c8dbc43834a5771f470965930f1294a6f6e'],
    [
      'SHA-512',
      'b2f8644db20fd50667740cf09e5f99e6fdb2402548dc62f458343361d887b6507039668de1dcc174325a3046ecb8c37e3d0c45f018ad831e96244f60fb4c195b',
    ],
    ['SHA3-224', 'c8f49b65e7d9cf7b720f4c129d498c681f073da117df3bc513097130'],
    ['SHA3-256', '7664385387c875c6fa9097cdc8757bbbfc362aaf2268e963d2891f71a2648472'],
    ['SHA3-384', '62a4a1f5a5c34eb6459d724bae37bd81240eafcd22f30d6c875070cee1a1ae4721239af0358651d3ccf311a89055da99'],
    [
      'SHA3-512',
      '36aa377475e1c37ff2187ec1c18f9620b156e6fa6dea289277f9336feca11993ec61cd6f3a37753048520851ddfc880fdb7a4a6ea4034695057ca6b52856c27b',
    ],
    ['SM3', '654dfa01365508b927a23d1b54af88025af2eeac68a025cf996819cf0e47719e'],
  ]);

  test('hex', () => {
    const values = Object.values(HMAC);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];
      const hex = map.get(name);

      if (!hex) {
        continue;
      }

      let hmac = Hmac.create(name, keyString).update(textBuffer);
      expect(hmac.hex()).toBe(hex);

      hmac = Hmac.create(name, keyString).update(textString);
      expect(hmac.hex()).toBe(hex);

      hmac = Hmac.create(name, keyBuffer).update(textBuffer);
      expect(hmac.hex()).toBe(hex);

      hmac = Hmac.create(name, keyBuffer).update(textString);
      expect(hmac.hex()).toBe(hex);

      hmac = Hmac.create(name, keyString);
      expect(hmac.update(textBuffer).hex()).toBe(hex);
      expect(hmac.update(textBuffer).hex()).toBe(hex);
    }
  });

  test('binary', () => {
    const values = Object.values(HMAC);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];
      const hex = map.get(name);

      if (!hex) {
        continue;
      }

      let hmac = Hmac.create(name, keyString).update(textBuffer);
      expect(hmac.binary()).toBe(Buffer.from(hex, 'hex').toString('binary'));

      hmac = Hmac.create(name, keyString).update(textString);
      expect(hmac.binary()).toBe(Buffer.from(hex, 'hex').toString('binary'));

      hmac = Hmac.create(name, keyBuffer).update(textBuffer);
      expect(hmac.binary()).toBe(Buffer.from(hex, 'hex').toString('binary'));

      hmac = Hmac.create(name, keyBuffer).update(textString);
      expect(hmac.binary()).toBe(Buffer.from(hex, 'hex').toString('binary'));

      hmac = Hmac.create(name, keyString);
      expect(hmac.update(textBuffer).binary()).toBe(Buffer.from(hex, 'hex').toString('binary'));
      expect(hmac.update(textBuffer).binary()).toBe(Buffer.from(hex, 'hex').toString('binary'));
    }
  });

  test('base64', () => {
    const values = Object.values(HMAC);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];
      const hex = map.get(name);

      if (!hex) {
        continue;
      }

      let hmac = Hmac.create(name, keyString).update(textBuffer);
      expect(hmac.base64()).toBe(Buffer.from(hex, 'hex').toString('base64'));

      hmac = Hmac.create(name, keyString).update(textString);
      expect(hmac.base64()).toBe(Buffer.from(hex, 'hex').toString('base64'));

      hmac = Hmac.create(name, keyBuffer).update(textBuffer);
      expect(hmac.base64()).toBe(Buffer.from(hex, 'hex').toString('base64'));

      hmac = Hmac.create(name, keyBuffer).update(textString);
      expect(hmac.base64()).toBe(Buffer.from(hex, 'hex').toString('base64'));

      hmac = Hmac.create(name, keyString);
      expect(hmac.update(textBuffer).base64()).toBe(Buffer.from(hex, 'hex').toString('base64'));
      expect(hmac.update(textBuffer).base64()).toBe(Buffer.from(hex, 'hex').toString('base64'));
    }
  });

  test('buffer', () => {
    const values = Object.values(HMAC);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];
      const hex = map.get(name);

      if (!hex) {
        continue;
      }

      let hmac = Hmac.create(name, keyString).update(textBuffer);
      expect(hmac.buffer()).toStrictEqual(Buffer.from(hex, 'hex'));

      hmac = Hmac.create(name, keyString).update(textString);
      expect(hmac.buffer()).toStrictEqual(Buffer.from(hex, 'hex'));

      hmac = Hmac.create(name, keyBuffer).update(textBuffer);
      expect(hmac.buffer()).toStrictEqual(Buffer.from(hex, 'hex'));

      hmac = Hmac.create(name, keyBuffer).update(textString);
      expect(hmac.buffer()).toStrictEqual(Buffer.from(hex, 'hex'));

      hmac = Hmac.create(name, keyString);
      expect(hmac.update(textBuffer).buffer()).toStrictEqual(Buffer.from(hex, 'hex'));
      expect(hmac.update(textBuffer).buffer()).toStrictEqual(Buffer.from(hex, 'hex'));
    }
  });

  test('digest', () => {
    const values = Object.values(HMAC);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];
      const hex = map.get(name);

      if (!hex) {
        continue;
      }

      let hmac = Hmac.create(name, keyString).update(textBuffer);
      expect(hmac.digest()).toStrictEqual(Buffer.from(hex, 'hex'));

      hmac = Hmac.create(name, keyString).update(textString);
      expect(hmac.digest()).toStrictEqual(Buffer.from(hex, 'hex'));

      hmac = Hmac.create(name, keyBuffer).update(textBuffer);
      expect(hmac.digest()).toStrictEqual(Buffer.from(hex, 'hex'));

      hmac = Hmac.create(name, keyBuffer).update(textString);
      expect(hmac.digest()).toStrictEqual(Buffer.from(hex, 'hex'));

      hmac = Hmac.create(name, keyString);
      expect(hmac.update(textBuffer).digest()).toStrictEqual(Buffer.from(hex, 'hex'));
      expect(hmac.update(textBuffer).digest()).toStrictEqual(Buffer.from(hex, 'hex'));
    }
  });

  test('uint8Array', () => {
    const values = Object.values(HMAC);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];
      const hex = map.get(name);

      if (!hex) {
        continue;
      }

      let hmac = Hmac.create(name, keyString).update(textBuffer);
      expect(hmac.uint8Array()).toStrictEqual(new Uint8Array(Buffer.from(hex, 'hex')));

      hmac = Hmac.create(name, keyString).update(textString);
      expect(hmac.uint8Array()).toStrictEqual(new Uint8Array(Buffer.from(hex, 'hex')));

      hmac = Hmac.create(name, keyBuffer).update(textBuffer);
      expect(hmac.uint8Array()).toStrictEqual(new Uint8Array(Buffer.from(hex, 'hex')));

      hmac = Hmac.create(name, keyBuffer).update(textString);
      expect(hmac.uint8Array()).toStrictEqual(new Uint8Array(Buffer.from(hex, 'hex')));

      hmac = Hmac.create(name, keyString);
      expect(hmac.update(textBuffer).uint8Array()).toStrictEqual(new Uint8Array(Buffer.from(hex, 'hex')));
      expect(hmac.update(textBuffer).uint8Array()).toStrictEqual(new Uint8Array(Buffer.from(hex, 'hex')));
    }
  });

  test('example', () => {
    const hex = String(map.get('SHA-256'));

    const digest = Hmac.create('sha256', keyString).update(textString).digest('base64url');
    expect(digest).toEqual(Buffer.from(hex, 'hex').toString('base64url'));

    const buffer = Hmac.create('sha256', keyString).update(textString).digest();
    expect(buffer).toStrictEqual(Buffer.from(hex, 'hex'));

    expect(Hmac.create('sha256', keyString).update(textString).binary()).toEqual(
      Buffer.from(hex, 'hex').toString('binary')
    );
    expect(Hmac.create('sha256', keyString).update(textString).hex()).toEqual(Buffer.from(hex, 'hex').toString('hex'));
    expect(Hmac.create('sha256', keyString).update(textString).base64()).toEqual(
      Buffer.from(hex, 'hex').toString('base64')
    );
    expect(Hmac.create('sha256', keyString).update(textString).buffer()).toEqual(Buffer.from(hex, 'hex'));
    expect(Hmac.create('sha256', keyString).update(textString).uint8Array()).toStrictEqual(
      new Uint8Array(Buffer.from(hex, 'hex'))
    );
  });
});
