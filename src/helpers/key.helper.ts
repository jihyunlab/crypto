import * as crypto from 'crypto';

export const KeyHelper = {
  async pbkdf2(
    length: number,
    password: string,
    salt: string,
    iterations: number
  ) {
    return crypto.pbkdf2Sync(password, salt, iterations, length, 'sha512');
  },
};
