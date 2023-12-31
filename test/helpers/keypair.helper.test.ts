import { Helper } from '../../src/index';
import * as crypto from 'crypto';

describe('KeyPair', () => {
  test('export(privateKey)', () => {
    const keyPair = Helper.keyPair.generate.p256();

    const exported = keyPair.privateKey.export({ type: 'pkcs8', format: 'der' });
    const privateKey = Helper.keyPair.generate.privateKey({ type: 'pkcs8', format: 'der', key: exported });

    expect(exported).toStrictEqual(privateKey.export({ type: 'pkcs8', format: 'der' }));
  });

  test('export(publicKey)', () => {
    const keyPair = Helper.keyPair.generate.p256();

    const exported = keyPair.publicKey.export({ type: 'spki', format: 'der' });
    const publicKey = Helper.keyPair.generate.publicKey({ type: 'spki', format: 'der', key: exported });

    expect(exported).toStrictEqual(publicKey.export({ type: 'spki', format: 'der' }));
  });

  test('generate(x25519)', () => {
    const keyPairA = Helper.keyPair.generate.x25519({
      modulusLength: 256 * 8,
      hashAlgorithm: 'sha256',
    });

    const keyPairB = Helper.keyPair.generate.x25519({
      modulusLength: 256 * 8,
      hashAlgorithm: 'sha256',
    });

    const agreeA = crypto.diffieHellman({
      publicKey: keyPairB.publicKey,
      privateKey: keyPairA.privateKey,
    });

    const agreeB = crypto.diffieHellman({
      publicKey: keyPairA.publicKey,
      privateKey: keyPairB.privateKey,
    });

    expect(agreeA).toStrictEqual(agreeB);
  });

  test('generate(x448)', () => {
    const keyPairA = Helper.keyPair.generate.x448({
      modulusLength: 256 * 8,
      hashAlgorithm: 'sha256',
    });

    const keyPairB = Helper.keyPair.generate.x448({
      modulusLength: 256 * 8,
      hashAlgorithm: 'sha256',
    });

    const agreeA = crypto.diffieHellman({
      publicKey: keyPairB.publicKey,
      privateKey: keyPairA.privateKey,
    });

    const agreeB = crypto.diffieHellman({
      publicKey: keyPairA.publicKey,
      privateKey: keyPairB.privateKey,
    });

    expect(agreeA).toStrictEqual(agreeB);
  });
});
