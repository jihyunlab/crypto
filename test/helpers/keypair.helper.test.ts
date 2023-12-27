import { Helper } from '../../src/index';
import * as crypto from 'crypto';

describe('Keypair', () => {
  test('export(privateKey)', () => {
    const keypair = Helper.keypair.generate.p256();

    const exported = keypair.privateKey.export({ type: 'pkcs8', format: 'der' });
    const privateKey = Helper.keypair.generate.privateKey({ type: 'pkcs8', format: 'der', key: exported });

    expect(exported).toStrictEqual(privateKey.export({ type: 'pkcs8', format: 'der' }));
  });

  test('export(publicKey)', () => {
    const keypair = Helper.keypair.generate.p256();

    const exported = keypair.publicKey.export({ type: 'spki', format: 'der' });
    const publicKey = Helper.keypair.generate.publicKey({ type: 'spki', format: 'der', key: exported });

    expect(exported).toStrictEqual(publicKey.export({ type: 'spki', format: 'der' }));
  });

  test('keypair(x25519)', () => {
    const keypairA = Helper.keypair.generate.x25519({
      modulusLength: 256 * 8,
      hashAlgorithm: 'sha256',
    });

    const keypairB = Helper.keypair.generate.x25519({
      modulusLength: 256 * 8,
      hashAlgorithm: 'sha256',
    });

    const agreeA = crypto.diffieHellman({
      publicKey: keypairB.publicKey,
      privateKey: keypairA.privateKey,
    });

    const agreeB = crypto.diffieHellman({
      publicKey: keypairA.publicKey,
      privateKey: keypairB.privateKey,
    });

    expect(agreeA).toStrictEqual(agreeB);
  });

  test('keypair(x448)', () => {
    const keypairA = Helper.keypair.generate.x448({
      modulusLength: 256 * 8,
      hashAlgorithm: 'sha256',
    });

    const keypairB = Helper.keypair.generate.x448({
      modulusLength: 256 * 8,
      hashAlgorithm: 'sha256',
    });

    const agreeA = crypto.diffieHellman({
      publicKey: keypairB.publicKey,
      privateKey: keypairA.privateKey,
    });

    const agreeB = crypto.diffieHellman({
      publicKey: keypairA.publicKey,
      privateKey: keypairB.privateKey,
    });

    expect(agreeA).toStrictEqual(agreeB);
  });
});
