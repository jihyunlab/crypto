# @jihyunlab/crypto

[![Version](https://img.shields.io/npm/v/@jihyunlab/crypto.svg?style=flat-square)](https://www.npmjs.com/package/@jihyunlab/crypto?activeTab=versions) [![Downloads](https://img.shields.io/npm/dt/@jihyunlab/crypto.svg?style=flat-square)](https://www.npmjs.com/package/@jihyunlab/crypto) [![Last commit](https://img.shields.io/github/last-commit/jihyunlab/crypto.svg?style=flat-square)](https://github.com/jihyunlab/crypto/graphs/commit-activity) [![License](https://img.shields.io/github/license/jihyunlab/crypto.svg?style=flat-square)](https://github.com/jihyunlab/crypto/blob/master/LICENSE) [![Linter](https://img.shields.io/badge/linter-eslint-blue?style=flat-square)](https://eslint.org) [![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)\
[![Build](https://github.com/jihyunlab/crypto/actions/workflows/build.yml/badge.svg)](https://github.com/jihyunlab/crypto/actions/workflows/build.yml) [![Lint](https://github.com/jihyunlab/crypto/actions/workflows/lint.yml/badge.svg)](https://github.com/jihyunlab/crypto/actions/workflows/lint.yml) [![codecov](https://codecov.io/gh/jihyunlab/crypto/graph/badge.svg?token=UW73ZNZY03)](https://codecov.io/gh/jihyunlab/crypto)

@jihyunlab/crypto was developed to enhance the convenience of implementing cryptographic functionalities in Node.js applications.

The encryption function is implemented with [Crypto](https://nodejs.org/api/crypto.html) in Node.js and provides encryption for AES 256 CBC and AES 256 GCM.

## Installation

```bash
npm i @jihyunlab/crypto
```

## Usage

You can easily encrypt and decrypt data with a simple method.

```
import { CIPHER, createCipher } from '@jihyunlab/crypto';

const cipher = await createCipher(CIPHER.AES_256_GCM, 'your secret key');

const encrypted = await cipher.encrypt('jihyunlab');
console.log(encrypted); // Uint8Array(37)[51, 174, 20, 84, 12, 141, 173, 206, 249, 11, 59, 112, 88, 223, 163, 211, 128, 234, 102, 116, 16, 224, 175, 45, 46, 52, 186, 141, 15, 243, 9, 120, 64, 27, 135, 169, 65]

const decrypted = await cipher.decrypt(encrypted);
console.log(decrypted); // Uint8Array(9)[106, 105, 104, 121, 117, 110, 108, 97, 98]

const buffer = Buffer.from(decrypted);
console.log(buffer.toString()); // jihyunlab
```

Provides encryption functionality for Uint8Array data.

```
const encrypted = await cipher.encrypt(
  new Uint8Array([106, 105, 104, 121, 117, 110, 108, 97, 98])
);
console.log(encrypted); // Uint8Array(37)[185, 95, 254, 103, 109, 250, 109, 50, 8, 218, 251, 74, 215, 108, 74, 86, 177, 82, 144, 154, 156, 120, 128, 169, 112, 236, 153, 23, 253, 164, 238, 159, 236, 17, 85, 26, 75]

const decrypted = await cipher.decrypt(encrypted);
console.log(decrypted); // Uint8Array(9)[106, 105, 104, 121, 117, 110, 108, 97, 98]
```

You can configure encryption options such as salt and iteration.

```
const cipher = await createCipher(CIPHER.AES_256_GCM, 'your secret key', {
  salt: 'salt',
  iterations: 256,
});
```

Provides hashing functionality for Uint8Array data.

```
import { HASH, createHash } from '@jihyunlab/crypto';

const hash = await createHash(HASH.SHA_256);

const hashed = await hash.digest(
  new Uint8Array([106, 105, 104, 121, 117, 110, 108, 97, 98])
);
console.log(hashed); // Uint8Array(32) [200, 111, 45, 209, 157, 58, 63, 244, 241, 200, 144, 165, 32, 243, 10, 145, 101, 204, 44, 179, 226, 63, 57, 208, 185, 93, 101, 0, 122, 198, 82, 100]
```

## @jihyunlab/web-crypto

[@jihyunlab/web-crypto](https://www.npmjs.com/package/@jihyunlab/web-crypto) implements encryption functionalities for web applications using the same interface as @jihyunlab/crypto.

Consider using @jihyunlab/web-crypto for decrypting encrypted data from @jihyunlab/crypto in web applications, or vice versa.

```
import { CIPHER, createCipher } from '@jihyunlab/web-crypto';

const cipher = await createCipher(CIPHER.AES_256_GCM, 'your secret key');
const encrypted = await cipher.encrypt('jihyunlab');
```

## Credits

Authored and maintained by JihyunLab <<info@jihyunlab.com>>

## License

Open source [licensed as MIT](https://github.com/jihyunlab/crypto/blob/master/LICENSE).
