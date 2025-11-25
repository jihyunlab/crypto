/**
 * @jest-environment node
 */
import { CRYPTO } from '../../src/interfaces/crypto.interface';
import { CryptoCreator } from '../../src/cryptos/crypto.creator';

describe('Crypto creator', () => {
  test(`Negative: create() - crypto does not exist.`, async () => {
    expect(async () => {
      await CryptoCreator.create('crypto' as unknown as CRYPTO, {});
    }).rejects.toThrow(Error('crypto does not exist.'));
  });
});
