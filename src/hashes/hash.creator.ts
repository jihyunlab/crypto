import { HASH, Hash } from '../interfaces/hash.interface';
import { NodeHash } from './node.hash';

export const HashCreator = {
  async create(hash: HASH) {
    let instance: Hash;

    switch (hash) {
      case HASH.SHA_256:
        instance = await NodeHash.create('sha256');
        break;
      case HASH.SHA_384:
        instance = await NodeHash.create('sha384');
        break;
      default:
        throw new Error(`${hash} does not exist.`);
    }

    return instance;
  },
};
