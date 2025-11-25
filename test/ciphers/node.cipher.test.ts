/**
 * @jest-environment node
 */
import { NodeCipher } from '../../src/ciphers/node.cipher';
import { KeyHelper } from '../../src/helpers/key.helper';

describe('Node cipher', () => {
  test(`Negative: encrypt() - key does not exist.`, async () => {
    const spy = jest.spyOn(KeyHelper as any, 'pbkdf2');
    spy.mockImplementation(() => {
      return undefined;
    });

    const cipher = await NodeCipher.create('aes-256-gcm', 256, 'password', 12);

    expect(async () => {
      await cipher.encrypt('text');
    }).rejects.toThrow(Error('key does not exist.'));

    spy.mockReset();
    spy.mockRestore();
  });

  test(`Negative: decrypt() - key does not exist.`, async () => {
    const spy = jest.spyOn(KeyHelper as any, 'pbkdf2');
    spy.mockImplementation(() => {
      return undefined;
    });

    const cipher = await NodeCipher.create('aes-256-gcm', 256, 'password', 12);

    expect(async () => {
      await cipher.decrypt('text');
    }).rejects.toThrow(Error('key does not exist.'));

    spy.mockReset();
    spy.mockRestore();
  });
});
