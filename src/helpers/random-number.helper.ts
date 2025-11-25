import * as crypto from 'crypto';

export const RandomNumberHelper = {
  async randomNumber4() {
    return String(crypto.randomInt(1000, 9999));
  },

  async randomNumber6() {
    return String(crypto.randomInt(100000, 999999));
  },

  async randomNumber8() {
    return String(crypto.randomInt(10000000, 99999999));
  },
};
