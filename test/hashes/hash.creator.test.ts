/**
 * @jest-environment jsdom
 */
import { HASH } from '../../src/interfaces/hash.interface';
import { HashCreator } from '../../src/hashes/hash.creator';

describe('Hash creator', () => {
  test(`Negative: create() - hash does not exist.`, async () => {
    expect(async () => {
      await HashCreator.create('hash' as unknown as HASH);
    }).rejects.toThrow(Error('hash does not exist.'));
  });
});
