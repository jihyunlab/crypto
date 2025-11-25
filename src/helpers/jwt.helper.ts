export const JwtHelper = {
  async createJwt(toBeSigned: Uint8Array, signature: Uint8Array) {
    const encodedToBeSigned = Buffer.from(toBeSigned).toString('utf8');
    const encodedSignature = Buffer.from(signature).toString('base64url');

    return `${encodedToBeSigned}.${encodedSignature}`;
  },

  async parseJwt(jwt: string) {
    const token = jwt.split('.');

    const header = JSON.parse(
      Buffer.from(token[0], 'base64url').toString('utf8')
    );
    const payload = JSON.parse(
      Buffer.from(token[1], 'base64url').toString('utf8')
    );
    const signature = new Uint8Array(Buffer.from(token[2], 'base64url'));
    const toBeSigned = new Uint8Array(
      Buffer.from(`${token[0]}.${token[1]}`, 'utf8')
    );

    return {
      header: header,
      payload: payload,
      signature: signature,
      toBeSigned: toBeSigned,
    };
  },

  async createToBeSigned(header: object, payload: object) {
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString(
      'base64url'
    );
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString(
      'base64url'
    );

    return new Uint8Array(
      Buffer.from(`${encodedHeader}.${encodedPayload}`, 'utf8')
    );
  },
};
