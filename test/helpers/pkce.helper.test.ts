/**
 * @jest-environment node
 */
import { PkceHelper } from '../../src/helpers/pkce.helper';

describe('Pkce helper', () => {
  test(`Positive: createS256CodeChallenge()`, async () => {
    const codeChallenge = await PkceHelper.createS256CodeChallenge('JihyunLab');

    expect(codeChallenge).toBe(
      Buffer.from(
        '1e84c1f3e55c80f69ec2033e124bd48bb858aff2a43b5740b537487a9cf59560',
        'hex'
      ).toString('base64url')
    );
  });

  test(`Positive: verifyS256CodeChallenge()`, async () => {
    const codeChallenge = await PkceHelper.createS256CodeChallenge('JihyunLab');
    const verified = await PkceHelper.verifyS256CodeChallenge(
      'JihyunLab',
      codeChallenge
    );

    expect(verified).toBe(true);
  });

  test(`Negative: verifyS256CodeChallenge()`, async () => {
    const codeChallenge = await PkceHelper.createS256CodeChallenge('JihyunLab');
    const verified = await PkceHelper.verifyS256CodeChallenge(
      'Wrong',
      codeChallenge
    );

    expect(verified).toBe(false);
  });
});
