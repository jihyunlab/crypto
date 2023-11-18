import { HASH, Hash } from '../src/index';

describe('Hash', () => {
  const textString = 'jihyunlab';
  const textBuffer = Buffer.from(textString, 'utf8');

  const map = new Map([
    ['SHA-224', 'bb09031c34196e1e3d6c74b88657f9c01d2a9adc6c6f0b12dd380b6e'],
    ['SHA-256', 'c86f2dd19d3a3ff4f1c890a520f30a9165cc2cb3e23f39d0b95d65007ac65264'],
    ['SHA-384', 'fafc0d25d3b79037e396608db8a27d1cfb7280da4dc51874b518c20073b890016aa89c8b6b17531b161538c3d8467970'],
    [
      'SHA-512',
      'd7031e6c0610acb32250d459264f5588e3a716815272421897cb23750984dd838bdf607f4c59ce07e5cc617c48fd270605733baabb33125286338e5cf2dec41f',
    ],
    ['SHA3-224', '113940c9dc5a2a3896466971a60f98c840b60f79360b996c4b8e08d0'],
    ['SHA3-256', 'a70a8244b2cc3cb993d879961d9fc74ec238a30b5164df576c1f8e31cb470dc8'],
    ['SHA3-384', 'a890779708b2627de32a44f1340a0eb85a6f078c4da999d7ff311a66dea7248a2e704a6d05ac66b5d3d0f9ca85ac85e1'],
    [
      'SHA3-512',
      '0853975fb2ae207be68ce49d2f0bc51f72fb9eaa3ffb66338ba08f5ef4c738bc09b2cfef71e5db74e9b1531360381213579174dd5d52713228bfac158e0d8518',
    ],
  ]);

  test('hex', () => {
    const values = Object.values(HASH);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];
      const hex = map.get(name);

      if (!hex) {
        continue;
      }

      let hash = Hash.create(name).update(textBuffer);
      expect(hash.hex()).toBe(hex);

      hash = Hash.create(name).update(textString);
      expect(hash.hex()).toBe(hex);

      hash = Hash.create(name);
      expect(hash.update(textBuffer).hex()).toBe(hex);
      expect(hash.update(textBuffer).hex()).toBe(hex);
    }
  });

  test('binary', () => {
    const values = Object.values(HASH);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];
      const hex = map.get(name);

      if (!hex) {
        continue;
      }

      let hash = Hash.create(name).update(textBuffer);
      expect(hash.binary()).toBe(Buffer.from(hex, 'hex').toString('binary'));

      hash = Hash.create(name).update(textString);
      expect(hash.binary()).toBe(Buffer.from(hex, 'hex').toString('binary'));

      hash = Hash.create(name);
      expect(hash.update(textBuffer).binary()).toBe(Buffer.from(hex, 'hex').toString('binary'));
      expect(hash.update(textBuffer).binary()).toBe(Buffer.from(hex, 'hex').toString('binary'));
    }
  });

  test('base64', () => {
    const values = Object.values(HASH);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];
      const hex = map.get(name);

      if (!hex) {
        continue;
      }

      let hash = Hash.create(name).update(textBuffer);
      expect(hash.base64()).toBe(Buffer.from(hex, 'hex').toString('base64'));

      hash = Hash.create(name).update(textString);
      expect(hash.base64()).toBe(Buffer.from(hex, 'hex').toString('base64'));

      hash = Hash.create(name);
      expect(hash.update(textBuffer).base64()).toBe(Buffer.from(hex, 'hex').toString('base64'));
      expect(hash.update(textBuffer).base64()).toBe(Buffer.from(hex, 'hex').toString('base64'));
    }
  });

  test('buffer', () => {
    const values = Object.values(HASH);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];
      const hex = map.get(name);

      if (!hex) {
        continue;
      }

      let hash = Hash.create(name).update(textBuffer);
      expect(hash.buffer()).toStrictEqual(Buffer.from(hex, 'hex'));

      hash = Hash.create(name).update(textString);
      expect(hash.buffer()).toStrictEqual(Buffer.from(hex, 'hex'));

      hash = Hash.create(name);
      expect(hash.update(textBuffer).buffer()).toStrictEqual(Buffer.from(hex, 'hex'));
      expect(hash.update(textBuffer).buffer()).toStrictEqual(Buffer.from(hex, 'hex'));
    }
  });

  test('digest', () => {
    const values = Object.values(HASH);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];
      const hex = map.get(name);

      if (!hex) {
        continue;
      }

      let hash = Hash.create(name).update(textBuffer);
      expect(hash.digest()).toStrictEqual(Buffer.from(hex, 'hex'));

      hash = Hash.create(name).update(textString);
      expect(hash.digest()).toStrictEqual(Buffer.from(hex, 'hex'));

      hash = Hash.create(name);
      expect(hash.update(textBuffer).digest()).toStrictEqual(Buffer.from(hex, 'hex'));
      expect(hash.update(textBuffer).digest()).toStrictEqual(Buffer.from(hex, 'hex'));
    }
  });

  test('uint8Array', () => {
    const values = Object.values(HASH);

    for (let i = 0; i < values.length; i++) {
      const name = values[i];
      const hex = map.get(name);

      if (!hex) {
        continue;
      }

      let hash = Hash.create(name).update(textBuffer);
      expect(hash.uint8Array()).toStrictEqual(new Uint8Array(Buffer.from(hex, 'hex')));

      hash = Hash.create(name).update(textString);
      expect(hash.uint8Array()).toStrictEqual(new Uint8Array(Buffer.from(hex, 'hex')));

      hash = Hash.create(name);
      expect(hash.update(textBuffer).uint8Array()).toStrictEqual(new Uint8Array(Buffer.from(hex, 'hex')));
      expect(hash.update(textBuffer).uint8Array()).toStrictEqual(new Uint8Array(Buffer.from(hex, 'hex')));
    }
  });
});
