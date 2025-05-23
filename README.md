# Serpent Cipher Algorithm

[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C++17 Ready](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)

---

## Table of Contents

- [Overview](#overview)
- [Historical Background](#historical-background)
- [Mathematics Behind Serpent](#mathematics-behind-serpent)
- [Modes of Operation](#modes-of-operation)
- [Key Sizes Supported](#key-sizes-supported)
- [Usage Examples](#usage-examples)
- [Security Notes and Disclaimer](#security-notes-and-disclaimer)
- [Performance](#performance)
- [License](#license)
- [References](#references)

---

## Overview

This header-only C++ implementation provides the [Serpent Block Cipher](https://en.wikipedia.org/wiki/Serpent_(cipher)), a symmetric-key cryptographic algorithm and one of the Advanced Encryption Standard (AES) finalists.  
It offers a modern, flexible, and easy-to-use interface supporting multiple modes of operation and key size variants.  
**This project is intended for educational and research purposes only.**

**Repository:** [MrkFrcsl98/Serpent_Algorithm](https://github.com/MrkFrcsl98/Serpent_Algorithm)  
**Author:** MrkFrcsl98

---

## Historical Background

Serpent was designed in 1998 by Ross Anderson, Eli Biham, and Lars Knudsen as a strong, conservative block cipher for the AES competition.  
While Rijndael was ultimately selected as the AES standard, Serpent is still considered one of the most secure block ciphers ever designed due to its high security margin and simple structure.

- **Block size:** 128 bits (16 bytes)
- **Number of rounds:** 32
- **Key sizes supported:** 128, 192, and 256 bits

Serpent is based on a substitution-permutation network (SPN) and employs bitslicing for fast and secure implementation on modern CPUs.

---

## Mathematics Behind Serpent

Serpent is a 32-round substitution-permutation network:

- **Substitution (S-Boxes):**  
  Eight different 4-bit S-boxes are used, applied in a "bitsliced" manner.
- **Permutation:**  
  Each round features a linear transformation to mix bits, except the last.
- **Key Schedule:**  
  Expands the user key into 33 round keys using rotations and S-boxes.

**Encryption Round:**
1. XOR with round key  
2. Substitution layer (S-box)  
3. Linear transformation (except final round)

**Decryption reverses this process.**

#### Bitslicing
Serpent's design is highly bitsliced, allowing efficient parallel operations using logical instructions.

---

## Modes of Operation

The implementation supports the following standard modes of operation:

| Mode Name | Description              | Padding Needed? | IV/Nonce Required? | Secure for Messages Larger Than Block? |
|-----------|-------------------------|-----------------|--------------------|----------------------------------------|
| **ECB**   | Electronic Codebook     | Yes (`PKCS#7`)  | No                 | ❌ (not recommended)                   |
| **CBC**   | Cipher Block Chaining   | Yes (`PKCS#7`)  | Yes (IV)           | ✔️                                     |
| **CFB**   | Cipher Feedback         | No              | Yes (IV)           | ✔️                                     |
| **OFB**   | Output Feedback         | No              | Yes (IV)           | ✔️                                     |
| **CTR**   | Counter                 | No              | Yes (Nonce)        | ✔️                                     |

> **Note:**  
> - IVs/Nonces must be unique and random for each encryption in CBC/CFB/OFB/CTR.
> - ECB mode should only be used for single-block messages or educational demos.

---

## Key Sizes Supported

| Option         | Enum Value             | Key Length (bytes) | Key Length (bits) |
|----------------|-----------------------|--------------------|-------------------|
| 128 bits       | `KEY_SIZE::BITS_128`  | 16                 | 128               |
| 192 bits       | `KEY_SIZE::BITS_192`  | 24                 | 192               |
| 256 bits       | `KEY_SIZE::BITS_256`  | 32                 | 256               |

---

## Usage Examples

### Include & Typedefs

```cpp
#include "serpent.hpp"
using serpent256 = Serpent<KEY_SIZE::BITS_256>;
```

### Key and IV Generation

```cpp
std::string key = KeyIVGenerator::generateKey(KEY_SIZE::BITS_256);
std::string iv  = KeyIVGenerator::generateIV(); // 16 bytes
```

### ECB Mode

```cpp
std::string plaintext = "Hello, Serpent!";
auto ciphertext = serpent256::ECB::Encrypt(plaintext, key);
// To hex
std::cout << "Ciphertext (hex): " << ciphertext.toHex().asString() << "\n";
auto decrypted = serpent256::ECB::Decrypt(ciphertext.asString(), key);
```

### CBC Mode

```cpp
auto cbc_cipher = serpent256::CBC::Encrypt(plaintext, key, iv);
auto cbc_plain  = serpent256::CBC::Decrypt(cbc_cipher.asString(), key, iv);
```

### CFB/OFB/CTR Modes

```cpp
auto cfb_cipher = serpent256::CFB::Encrypt(plaintext, key, iv);
auto cfb_plain  = serpent256::CFB::Decrypt(cfb_cipher.asString(), key, iv);

auto ofb_cipher = serpent256::OFB::Encrypt(plaintext, key, iv);
auto ofb_plain  = serpent256::OFB::Decrypt(ofb_cipher.asString(), key, iv);

auto ctr_cipher = serpent256::CTR::Encrypt(plaintext, key, iv); // IV acts as nonce
auto ctr_plain  = serpent256::CTR::Decrypt(ctr_cipher.asString(), key, iv);
```

### Encoding and Conversion Utilities

```cpp
auto base64 = ciphertext.toBase64().asString();
auto from64 = SerpentResult(base64).fromBase64().asString();
auto hexstr = ciphertext.toHex().asString();
auto orig   = SerpentResult(hexstr).fromHex().asString();
```

---

## Security Notes and Disclaimer

> :warning: **Educational Use Only!**
>
> - This code is provided for learning, academic, and research purposes.
> - It has **not** been security audited or tested for use in production.
> - Cryptographic code is easy to get wrong.  
> - Do **NOT** use this implementation to protect sensitive or confidential data.
> - Use only after a full, independent security review.

---

## Performance

- Written in modern, portable C++17.
- Bitsliced implementation for efficient block processing.
- Suitable for experimentation, not optimized for high-throughput production use.

---

## License

This project is licensed under the MIT License.


## References

- [Serpent Official Submission to AES](https://www.cl.cam.ac.uk/~rja14/serpent.html)
- [Wikipedia: Serpent (cipher)](https://en.wikipedia.org/wiki/Serpent_(cipher))
- [The Design of Rijndael: AES - The Advanced Encryption Standard](https://www.springer.com/gp/book/9783540425809)
- [NIST AES Competition](https://csrc.nist.gov/projects/advanced-encryption-standard)

---

## Authors

- [MrkFrcsl98](https://github.com/MrkFrcsl98)
- Contributors as listed in source
