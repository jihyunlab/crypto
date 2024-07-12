/**
 * @jest-environment node
 */
import { NodeCryptoCipher } from '../../src/ciphers/node-crypto.service';
import { Key } from '../../src/helpers/key.helper';

describe('Node crypto service', () => {
  test(`Negative: encrypt() - key does not exist.`, async () => {
    const spy = jest.spyOn(Key as any, 'pbkdf2');
    spy.mockImplementation(() => {
      return undefined;
    });

    const cipher = await NodeCryptoCipher.create(
      'aes-256-gcm',
      256,
      'password',
      12
    );

    expect(async () => {
      await cipher.encrypt('text');
    }).rejects.toThrow(Error('key does not exist.'));

    spy.mockReset();
    spy.mockRestore();
  });

  test(`Negative: decrypt() - key does not exist.`, async () => {
    const spy = jest.spyOn(Key as any, 'pbkdf2');
    spy.mockImplementation(() => {
      return undefined;
    });

    const cipher = await NodeCryptoCipher.create(
      'aes-256-gcm',
      256,
      'password',
      12
    );

    expect(async () => {
      await cipher.decrypt('text');
    }).rejects.toThrow(Error('key does not exist.'));

    spy.mockReset();
    spy.mockRestore();
  });
});
