import * as crypto from 'crypto';

export const PkceHelper = {
  async createS256CodeChallenge(codeVerifier: string) {
    return crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest()
      .toString('base64url');
  },

  async verifyS256CodeChallenge(codeVerifier: string, codeChallenge: string) {
    if (
      (await this.createS256CodeChallenge(codeVerifier)).toUpperCase() ===
      codeChallenge.toUpperCase()
    ) {
      return true;
    }

    return false;
  },
};
