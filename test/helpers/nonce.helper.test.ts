import { AEAD, Helper } from '../../src/index';

describe('Nonce', () => {
  test('normalize(): exception(iv not found)', () => {
    Helper.cipher.info = jest.fn().mockImplementationOnce(() => {
      return {};
    });

    expect(() => {
      Helper.nonce.normalize(AEAD.AES_256_GCM, 'key');
    }).toThrow(Error);
  });

  test('generate(): exception(iv not found)', () => {
    Helper.cipher.info = jest.fn().mockImplementationOnce(() => {
      return {};
    });

    expect(() => {
      Helper.nonce.generate(AEAD.AES_256_GCM);
    }).toThrow(Error);
  });
});
