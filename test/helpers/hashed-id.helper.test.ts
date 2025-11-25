/**
 * @jest-environment node
 */
import { HashedIdHelper } from '../../src/helpers/hashed-id.helper';

describe('Hashed id helper', () => {
  test(`Positive: hashedId16()`, async () => {
    const hashedId16 = await HashedIdHelper.hashedId16('JihyunLab');

    expect(hashedId16).toBe('b858aff2a43b5740b537487a9cf59560'.toUpperCase());
  });

  test(`Positive: hashedId32()`, async () => {
    const hashedId32 = await HashedIdHelper.hashedId32('JihyunLab');

    expect(hashedId32).toBe(
      '1e84c1f3e55c80f69ec2033e124bd48bb858aff2a43b5740b537487a9cf59560'.toUpperCase()
    );
  });

  test(`Positive: hashedRandomUuid16()`, async () => {
    const hashedRandomUuid16 = await HashedIdHelper.hashedRandomUuid16();

    expect(hashedRandomUuid16.length).toBe(32);
  });

  test(`Positive: hashedRandomUuid32()`, async () => {
    const hashedRandomUuid32 = await HashedIdHelper.hashedRandomUuid32();

    expect(hashedRandomUuid32.length).toBe(64);
  });
});
