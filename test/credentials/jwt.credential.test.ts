import { Asymmetric, HASH, HMAC, Helper, Hmac } from '../../src/index';

describe('Jwt', () => {
  test('HS256(empty secret)', () => {
    const jsonHeader = {
      alg: 'HS256',
      typ: 'JWT',
    };

    const jsonPayload = {
      sub: '1234567890',
      name: 'John Doe',
      iat: 1516239022,
    };

    const secret = '';

    const testHeader = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
    const testPayload = 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ';
    const testSignature = 'he0ErCNloe4J7Id0Ry2SEDg09lKkZkfsRiGsdX_vgEg';

    const header = Buffer.from(JSON.stringify(jsonHeader)).toString('base64url');
    const payload = Buffer.from(JSON.stringify(jsonPayload)).toString('base64url');

    expect(header).toBe(testHeader);
    expect(payload).toBe(testPayload);

    const input = `${testHeader}.${testPayload}`;

    const signature = Hmac.create(HMAC.SHA256, secret).update(input).base64url();
    expect(signature).toBe(testSignature);
  });

  test('HS256(secret)', () => {
    const jsonHeader = {
      alg: 'HS256',
      typ: 'JWT',
    };

    const jsonPayload = {
      sub: '1234567890',
      name: 'John Doe',
      iat: 1516239022,
    };

    const secret = '8cb9f3eef4f72946f1fbd1c08a8bd5dfad0d38c187999175e9610f405e666203';

    const testHeader = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
    const testPayload = 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ';
    const testSignature = 'Fk-95l4iKZvhJBRnJ6pWnbU5YO3d7or0xvlZDgifLFo';

    const header = Buffer.from(JSON.stringify(jsonHeader)).toString('base64url');
    const payload = Buffer.from(JSON.stringify(jsonPayload)).toString('base64url');

    expect(header).toBe(testHeader);
    expect(payload).toBe(testPayload);

    const input = `${testHeader}.${testPayload}`;

    const signature = Hmac.create(HMAC.SHA256, secret).update(input).base64url();
    expect(signature).toBe(testSignature);
  });

  test('ES256', () => {
    const jsonHeader = {
      alg: 'ES256',
      typ: 'JWT',
    };

    const jsonPayload = {
      sub: '1234567890',
      name: 'John Doe',
      admin: true,
      iat: 1516239022,
    };

    const testHeader = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9';
    const testPayload = 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0';
    const testSignature = 'nRhr_v0pAjm2vYBqzP-pFdcAcASZf4KdYN0cgzinQlQQDSVSz0FB_JXOGwSR9lwzfX7pKQ0op2Yy1fFAjyqWcQ';

    const header = Buffer.from(JSON.stringify(jsonHeader)).toString('base64url');
    const payload = Buffer.from(JSON.stringify(jsonPayload)).toString('base64url');

    expect(header).toBe(testHeader);
    expect(payload).toBe(testPayload);

    const privateKey = Helper.keypair.generate.privateKey({
      key: {
        kty: 'EC',
        crv: 'P-256',
        x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
        y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        d: 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
      },
      format: 'jwk',
    });

    const publicKey = Helper.keypair.generate.publicKey({
      key: {
        kty: 'EC',
        crv: 'P-256',
        x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
        y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
      },
      format: 'jwk',
    });

    const input = Buffer.from(`${header}.${payload}`, 'ascii');

    const signer = Asymmetric.create.signer({ key: privateKey, dsaEncoding: 'ieee-p1363' });
    const signature = signer.sign(input).toString('base64url');

    const verifier = Asymmetric.create.verifier({ key: publicKey, dsaEncoding: 'ieee-p1363' });

    expect(verifier.verify(input, Buffer.from(testSignature, 'base64url'))).toBe(true);
    expect(verifier.verify(input, Buffer.from(signature, 'base64url'))).toBe(true);
  });

  test('ECDSA P-256 SHA-256(JWS - RFC 7515: A.3 Example JWS Using ECDSA P-256 SHA-256)', () => {
    const jsonHeader = { alg: 'ES256' };
    const textPayload = `{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}`;

    const testProtectedHeader = 'eyJhbGciOiJFUzI1NiJ9';
    const testPayload =
      'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
    const testSignature = 'DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q';

    const protectedHeader = Buffer.from(JSON.stringify(jsonHeader)).toString('base64url');
    const payload = Buffer.from(textPayload).toString('base64url');
    const payloadBuffer = Buffer.from(`{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}`);

    const testPayloadBuffer = Buffer.from([
      123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48,
      56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46,
      99, 111, 109, 47, 105, 115, 95, 114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125,
    ]);

    expect(payloadBuffer).toStrictEqual(testPayloadBuffer);

    expect(protectedHeader).toBe(testProtectedHeader);
    expect(payload).toBe(testPayload);

    const privateKey = Helper.keypair.generate.privateKey({
      key: {
        kty: 'EC',
        crv: 'P-256',
        x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
        y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        d: 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
      },
      format: 'jwk',
    });

    const publicKey = Helper.keypair.generate.publicKey({
      key: {
        kty: 'EC',
        crv: 'P-256',
        x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
        y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
      },
      format: 'jwk',
    });

    const input = Buffer.from(`${protectedHeader}.${payload}`, 'ascii');

    let signer = Asymmetric.create.signer({ key: privateKey, dsaEncoding: 'ieee-p1363' });
    let signature = signer.sign(input).toString('base64url');

    let verifier = Asymmetric.create.verifier({ key: publicKey, dsaEncoding: 'ieee-p1363' });

    expect(verifier.verify(input, Buffer.from(testSignature, 'base64url'))).toBe(true);
    expect(verifier.verify(input, Buffer.from(signature, 'base64url'))).toBe(true);

    signer = Asymmetric.create.signer({ key: privateKey, dsaEncoding: 'ieee-p1363' }, HASH.SHA256);
    signature = signer.sign(input).toString('base64url');

    expect(verifier.verify(input, Buffer.from(signature, 'base64url'))).toBe(true);

    verifier = Asymmetric.create.verifier({ key: publicKey, dsaEncoding: 'ieee-p1363' }, HASH.SHA256);
    expect(verifier.verify(input, Buffer.from(signature, 'base64url'))).toBe(true);
  });
});
