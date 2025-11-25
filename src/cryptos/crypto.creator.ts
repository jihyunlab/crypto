import { CRYPTO, Crypto, CryptoOptions } from '../interfaces/crypto.interface';
import { NodeCrypto } from './node.crypto';

export const CryptoCreator = {
  async create(crypto: CRYPTO, options?: CryptoOptions) {
    let instance: Crypto;

    let modulusLength: number | undefined;
    let use: string | undefined;

    if (
      options &&
      options.modulusLength !== undefined &&
      options.modulusLength !== null
    ) {
      modulusLength = options.modulusLength;
    }

    if (options && options.use !== undefined && options.use !== null) {
      use = options.use;
    }

    switch (crypto) {
      case CRYPTO.RSA_SHA384:
        instance = await NodeCrypto.create(
          'rsa',
          'RSA-SHA384',
          'RSA',
          'RS384',
          use || 'sig',
          modulusLength
        );
        break;
      default:
        throw new Error(`${crypto} does not exist.`);
    }

    return instance;
  },
};
