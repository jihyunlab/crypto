import * as crypto from 'crypto';

export const HashedIdHelper = {
  async hashedId16(id: string) {
    return crypto
      .createHash('sha256')
      .update(id)
      .digest()
      .subarray(-16)
      .toString('hex')
      .toUpperCase();
  },

  async hashedId32(id: string) {
    return crypto
      .createHash('sha256')
      .update(id)
      .digest()
      .subarray(-32)
      .toString('hex')
      .toUpperCase();
  },

  async hashedRandomUuid16() {
    return crypto
      .createHash('sha256')
      .update(crypto.randomUUID())
      .digest()
      .subarray(-16)
      .toString('hex')
      .toUpperCase();
  },

  async hashedRandomUuid32() {
    return crypto
      .createHash('sha256')
      .update(crypto.randomUUID())
      .digest()
      .subarray(-32)
      .toString('hex')
      .toUpperCase();
  },
};
