# @jihyunlab/crypto

[![Version](https://img.shields.io/npm/v/@jihyunlab/crypto.svg?style=flat-square)](https://www.npmjs.com/package/@jihyunlab/crypto?activeTab=versions) [![Downloads](https://img.shields.io/npm/dt/@jihyunlab/crypto.svg?style=flat-square)](https://www.npmjs.com/package/@jihyunlab/crypto) [![Last commit](https://img.shields.io/github/last-commit/jihyunlab/crypto.svg?style=flat-square)](https://github.com/jihyunlab/crypto/graphs/commit-activity) [![License](https://img.shields.io/github/license/jihyunlab/crypto.svg?style=flat-square)](https://github.com/jihyunlab/crypto/blob/master/LICENSE)

@jihyunlab/crypto was developed to increase the convenience of implementing cryptographic functions.\
@jihyunlab/crypto provides hash, HMAC, and symmetric-key algorithm functions, and functions related to actual encryption use encryption module of Node.js.

## Requirements

Node.js

## Setup

```bash
npm i @jihyunlab/crypto
```

## Hash

### Usage

You can generate hashes using any of the predefined hash algorithm types.

```javascript
import { Hash, HASH } from '@jihyunlab/crypto';

const hex = Hash.create(HASH.SHA256).update('string').hex();
```

You can use a buffer to generate a hash.

```javascript
const hex = Hash.create(HASH.SHA256).update(Buffer.from('string')).hex();
```

You can use predefined functions to select the type of hash to generate.

```javascript
Hash.create(HASH.SHA256).update('string').hex();
Hash.create(HASH.SHA256).update('string').binary();
Hash.create(HASH.SHA256).update('string').base64();
Hash.create(HASH.SHA256).update('string').buffer();
Hash.create(HASH.SHA256).update('string').uint8Array();
```

If the algorithm you want to use is not defined, you can manually enter the algorithm and hash type to generate.\
The input algorithm and hash must be types defined in Node.js.

```javascript
Hash.create('sha256').update('string').digest('base64url');
```

## HMAC

### Usage

```javascript
import { Hmac, HMAC } from '@jihyunlab/crypto';

const hex = Hmac.create(HMAC.SHA256, 'key').update('string').hex();
const buffer = Hmac.create(HMAC.SHA256, Buffer.from('key')).update(Buffer.from('string')).buffer();
```

## Symmetric-key algorithm

Symmetric-key algorithm is an encryption technique that uses the same key for encryption and decryption.

### Usage

Encryption functions can be implemented using predefined symmetric-key algorithm types and separately provided functions.

```javascript
import { Cipher, Helper, CIPHER, PBKDF, HASH } from '@jihyunlab/crypto';

// Generates a key for the encryption algorithm.
const key = Helper.key.generate(CIPHER.AES_256_CBC, 'password', 'salt');

// Create an IV(Initialization Vector) for encryption.
const iv = Helper.iv.generate(CIPHER.AES_256_CBC);

const encrypted = Cipher.create(CIPHER.AES_256_CBC, key).encrypt.hex('string', iv);
const decrypted = Cipher.create(CIPHER.AES_256_CBC, key).decrypt.hex(encrypted, iv);
```

You can implement cryptographic functions using buffers.

```javascript
const key = Helper.key.generate(CIPHER.AES_256_CBC, Buffer.from('password'), Buffer.from('salt'));
const iv = Helper.iv.generate(CIPHER.AES_256_CBC);

const encrypted = Cipher.create(CIPHER.AES_256_CBC, key).encrypt.buffer(Buffer.from('string'), iv);
const decrypted = Cipher.create(CIPHER.AES_256_CBC, key).decrypt.buffer(encrypted, iv);
```

You can use predefined functions to select the output type of the encrypted text and the input type of the text to be decrypted.

```javascript
Cipher.create(CIPHER.AES_256_CBC, key).encrypt.hex('string', iv);
Cipher.create(CIPHER.AES_256_CBC, key).decrypt.hex(encrypted, iv);

Cipher.create(CIPHER.AES_256_CBC, key).encrypt.binary('string', iv);
Cipher.create(CIPHER.AES_256_CBC, key).decrypt.binary(encrypted, iv);

Cipher.create(CIPHER.AES_256_CBC, key).encrypt.base64('string', iv);
Cipher.create(CIPHER.AES_256_CBC, key).decrypt.base64(encrypted, iv);

Cipher.create(CIPHER.AES_256_CBC, key).encrypt.buffer(Buffer.from('string'), iv);
Cipher.create(CIPHER.AES_256_CBC, key).decrypt.buffer(encrypted, iv);

Cipher.create(CIPHER.AES_256_CBC, key).encrypt.uint8Array(Buffer.from('string'), iv);
Cipher.create(CIPHER.AES_256_CBC, key).decrypt.uint8Array(encrypted, iv);
```

If the algorithm you want to use is not defined, you can enter the algorithm directly and select the input and output types for the encrypted and decrypted text.\
The input algorithm and input and output text types must be types defined in Node.js.

```javascript
const encrypted = Cipher.create(CIPHER.AES_256_CBC, key).encrypt.string('string', iv, 'utf8', 'base64url');
const decrypted = Cipher.create(CIPHER.AES_256_CBC, key).decrypt.string(encrypted, iv, 'base64url', 'utf8');
```

## Symmetric-key algorithm(AEAD)

AEAD(Authenticated Encryption with Associated Data) is an encryption technology that provides integrity through MAC calculation during encryption.

### Usage

Encryption functions can be implemented using predefined encryption algorithm types and separately provided functions.

```javascript
import { Aead, Helper, AEAD, PBKDF, HASH } from '@jihyunlab/crypto';

// Generates a key for the encryption algorithm.
const key = Helper.key.generate(AEAD.AES_256_CCM, 'password', 'salt');

// Create an nonce for encryption.
const nonce = Helper.nonce.generate(AEAD.AES_256_CCM);

const encrypted = Aead.create(AEAD.AES_256_CCM, key).encrypt.hex('string', nonce);
const decrypted = Aead.create(AEAD.AES_256_CCM, key).decrypt.hex(encrypted.text, encrypted.tag, nonce);
```

You can implement cryptographic functions using buffers.

```javascript
const key = Helper.key.generate(AEAD.AES_256_CCM, 'password', 'salt');
const nonce = Helper.nonce.generate(AEAD.AES_256_CCM);

const encrypted = Aead.create(AEAD.AES_256_CCM, key).encrypt.buffer(Buffer.from('string'), nonce);
const decrypted = Aead.create(AEAD.AES_256_CCM, key).decrypt.buffer(encrypted.text, encrypted.tag, nonce);
```

You can use it by directly entering the key, nonce, and IV.\
The input value can be converted to a value of a size suitable for the algorithm using the normalize function.

```javascript
const key = Helper.key.normalize(AEAD.AES_256_CCM, Buffer.from('key'));
const nonce = Helper.nonce.normalize(AEAD.AES_256_CCM, Buffer.from('nonce'));
```

## Credits

Authored and maintained by JihyunLab <<info@jihyunlab.com>>

## License

Open source [licensed as MIT](https://github.com/jihyunlab/crypto/blob/master/LICENSE).
