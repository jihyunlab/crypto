import { Helper } from '../../src/index';

describe('Cipher', () => {
  test('info(): exception(not found)', () => {
    expect(() => {
      Helper.cipher.info('temp');
    }).toThrow(Error);
  });

  test('hashes()', () => {
    const hashes = Helper.cipher.hashes();
    expect(hashes).not.toHaveLength(0);
  });

  test('ciphers()', () => {
    const ciphers = Helper.cipher.ciphers();
    expect(ciphers).not.toHaveLength(0);
  });

  test('curves()', () => {
    const curves = Helper.cipher.curves();
    expect(curves).not.toHaveLength(0);
  });
});
