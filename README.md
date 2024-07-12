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
import { CIPHER, Crypto } from '@jihyunlab/crypto';

const cipher = await Crypto.createCipher(CIPHER.AES_256_GCM, 'your secret key');

const encrypted = await cipher.encrypt('jihyunlab');
console.log(encrypted); // 89b1e3c2996e08d5549ecb9d625faca6db785c7d0f9ba51c3985e80ae1143263273308f5eb

const decrypted = await cipher.decrypt(encrypted);
console.log(decrypted); // jihyunlab
```

Provides encryption functionality for Uint8Array data.

```
const encrypted = await cipher.encrypt(new Uint8Array([106, 105, 104, 121, 117, 110, 108, 97, 98]));
console.log(encrypted); // Uint8Array(37) [110, 50, 51, 130, 66, 155, 136, 153, 236, 22, 148, 154, 231, 165, 223, 244, 173, 26, 206, 51, 133, 143, 133, 188, 4, 101, 208, 80, 218, 1, 108, 58, 201, 13, 70, 7, 83]

const decrypted = await cipher.decrypt(encrypted);
console.log(decrypted); // Uint8Array(9) [106, 105, 104, 121, 117, 110, 108, 97, 98]
```

## @jihyunlab/web-crypto

[@jihyunlab/web-crypto](https://www.npmjs.com/package/@jihyunlab/web-crypto) implements encryption functionalities for web applications using the same interface as @jihyunlab/crypto.

Consider using @jihyunlab/web-crypto for decrypting encrypted data from @jihyunlab/crypto in web applications, or vice versa.

## Credits

Authored and maintained by JihyunLab <<info@jihyunlab.com>>

## License

Open source [licensed as MIT](https://github.com/jihyunlab/crypto/blob/master/LICENSE).
