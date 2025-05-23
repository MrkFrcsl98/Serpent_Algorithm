// ============================================================================
//  serpent.hpp - Serpent Cipher Implementation
//  Copyright (c) 2024 666ghosthost666 and contributors
//
//  This software is provided 'as-is', without any express or implied warranty.
//  In no event will the authors be held liable for any damages arising from
//  the use of this software. Permission is granted to anyone to use this
//  software for any purpose, including commercial applications, and to alter
//  it and redistribute it freely, subject to the following restrictions:
//
//  1. The origin of this software must not be misrepresented; you must not
//     claim that you wrote the original software. If you use this software
//     in a product, an acknowledgment in the product documentation is required.
//
//  2. Altered source versions must be plainly marked as such, and must not be
//     misrepresented as being the original software.
//
//  3. This notice may not be removed or altered from any source distribution.
//
//  SECURITY WARNING:
//  =================
//  This code is provided for educational and research purposes only.
//  Cryptographic implementations are extremely difficult to implement
//  correctly and securely. Do not use this code in production systems
//  without a full and independent security review. The authors make no
//  guarantees regarding the security or suitability of this implementation
//  for any purpose.
//
//  USE AT YOUR OWN RISK.
// ============================================================================

#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

// ========== Attribute Macros ==========
#if defined(__GNUC__) || defined(__clang__)
#define __attr_nodiscard __attribute__((warn_unused_result))
#define __attr_malloc __attribute__((malloc))
#define __attr_hot __attribute__((hot))
#define __attr_cold __attribute__((cold))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define __attr_nodiscard
#define __attr_malloc
#define __attr_hot
#define __attr_cold
#define likely(x) (x)
#define unlikely(x) (x)
#endif

#ifdef __cplusplus
#define __restrict__ __restrict
#define __noexcept noexcept
#define __const_noexcept noexcept
#else
#define __restrict__ restrict
#define __noexcept
#define __const_noexcept
#endif

/**
 * @brief Enum for supported key sizes (in bytes).
 */
enum class KEY_SIZE : size_t
{
    BITS_128 = 16,
    BITS_192 = 24,
    BITS_256 = 32
};

/** @brief Block cipher modes. */
struct ECB_Mode
{
};
struct CBC_Mode
{
};
struct CFB_Mode
{
};
struct OFB_Mode
{
};
struct CTR_Mode
{
};

/// @brief Internal error handling for the Serpent cipher.
namespace serpent_detail
{
/**
 * @brief Throws a runtime error with the provided message.
 * @param msg The error message.
 */
[[noreturn]] __attr_cold inline void fail(const char *msg)
{
    throw std::runtime_error(msg);
}
} // namespace serpent_detail

/// @brief Utility namespace for base64, hex, and binary encoding/decoding.
namespace serpent_util
{
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char b64_pad = '=';

inline std::string toHex(const std::string &data)
{
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t b : data)
    {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0xF]);
    }
    return out;
}

inline std::string fromHex(const std::string &hexStr)
{
    std::string out;
    if (hexStr.size() % 2 != 0)
        serpent_detail::fail("Odd length hex string");
    out.reserve(hexStr.size() / 2);
    for (size_t i = 0; i < hexStr.size(); i += 2)
    {
        uint8_t hi = static_cast<uint8_t>(std::stoi(hexStr.substr(i, 1), nullptr, 16));
        uint8_t lo = static_cast<uint8_t>(std::stoi(hexStr.substr(i + 1, 1), nullptr, 16));
        out.push_back((hi << 4) | lo);
    }
    return out;
}

inline std::string toBinary(const std::string &data)
{
    std::string out;
    out.reserve(data.size() * 8);
    for (uint8_t b : data)
    {
        for (int i = 7; i >= 0; --i)
            out.push_back((b & (1 << i)) ? '1' : '0');
    }
    return out;
}

inline std::string fromBinary(const std::string &bin)
{
    if (bin.size() % 8 != 0)
        serpent_detail::fail("Binary string size must be multiple of 8");
    std::string out;
    for (size_t i = 0; i < bin.size(); i += 8)
    {
        uint8_t val = 0;
        for (int j = 0; j < 8; ++j)
        {
            val = (val << 1) | (bin[i + j] == '1' ? 1 : 0);
        }
        out.push_back(val);
    }
    return out;
}

inline std::string toBase64(const std::string &data)
{
    std::string out;
    int val = 0, valb = -6;
    for (uint8_t c : data)
    {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0)
        {
            out.push_back(b64_table[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        out.push_back(b64_table[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4)
        out.push_back(b64_pad);
    return out;
}

inline std::string fromBase64(const std::string &b64)
{
    int val = 0, valb = -8;
    std::string out;
    for (uint8_t c : b64)
    {
        if (c == b64_pad)
            break;
        const char *p = std::find(b64_table, b64_table + 64, c);
        if (p == b64_table + 64)
            break;
        val = (val << 6) + (p - b64_table);
        valb += 6;
        if (valb >= 0)
        {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}
} // namespace serpent_util

/**
 * @class KeyIVGenerator
 * @brief Utility class for securely generating random keys and IVs.
 */
class KeyIVGenerator
{
  public:
    static std::string generateKey(KEY_SIZE keySize)
    {
        size_t size = static_cast<size_t>(keySize);
        std::string key(size, '\0');
        randomFill(reinterpret_cast<uint8_t *>(&key[0]), size);
        return key;
    }
    static std::string generateIV(size_t ivSize = 16)
    {
        std::string iv(ivSize, '\0');
        randomFill(reinterpret_cast<uint8_t *>(&iv[0]), ivSize);
        return iv;
    }
    static std::string toHex(const std::string &data)
    {
        return serpent_util::toHex(data);
    }

  private:
    static void randomFill(uint8_t *buf, size_t n)
    {
        std::random_device rd;
        for (size_t i = 0; i < n; ++i)
        {
            buf[i] = static_cast<uint8_t>(rd());
        }
    }
};

/**
 * @class SerpentResult
 * @brief Wrapper for encrypted/decrypted results supporting method chaining and conversion utilities.
 */
class SerpentResult
{
    std::string data_;

  public:
    SerpentResult(const std::string &data) : data_(data)
    {
    }
    SerpentResult toHex() const
    {
        return SerpentResult(serpent_util::toHex(data_));
    }
    SerpentResult fromHex() const
    {
        return SerpentResult(serpent_util::fromHex(data_));
    }
    SerpentResult toBase64() const
    {
        return SerpentResult(serpent_util::toBase64(data_));
    }
    SerpentResult fromBase64() const
    {
        return SerpentResult(serpent_util::fromBase64(data_));
    }
    SerpentResult toBinary() const
    {
        return SerpentResult(serpent_util::toBinary(data_));
    }
    SerpentResult fromBinary() const
    {
        return SerpentResult(serpent_util::fromBinary(data_));
    }
    SerpentResult toString() const
    {
        return *this;
    }
    SerpentResult toVector() const
    {
        return *this;
    }
    std::string asString() const
    {
        return data_;
    }
    std::vector<uint8_t> asVector() const
    {
        return std::vector<uint8_t>(data_.begin(), data_.end());
    }
    operator std::string() const
    {
        return data_;
    }
    operator std::vector<uint8_t>() const
    {
        return asVector();
    }
};

/**
 * @class Serpent
 * @brief Flexible, template-based implementation of the Serpent block cipher.
 * @tparam KEY_SZ The key size (default 256 bits).
 */
template <KEY_SIZE KEY_SZ = KEY_SIZE::BITS_256> class Serpent
{
  public:
    using uint = uint32_t;
    using uchar = uint8_t;
    static constexpr size_t BlockSize = 16;
    static constexpr size_t KeySize = static_cast<size_t>(KEY_SZ);
    static constexpr size_t Rounds = 32;
    using Block = std::array<uint, 4>;
    using SubKeys = std::array<Block, Rounds + 1>;

    // =================== STATIC ACCESS STRUCTS FOR ALL MODES =======================
    struct ECB
    {
        static SerpentResult Encrypt(const std::string &plaintext, const std::string &key)
        {
            Serpent cipher;
            return SerpentResult(cipher.encryptECB(plaintext, key));
        }
        static SerpentResult Decrypt(const std::string &ciphertext, const std::string &key)
        {
            Serpent cipher;
            return SerpentResult(cipher.decryptECB(ciphertext, key));
        }
    };
    struct CBC
    {
        static SerpentResult Encrypt(const std::string &plaintext, const std::string &key, const std::string &iv)
        {
            Serpent cipher;
            return SerpentResult(cipher.encryptCBC(plaintext, key, iv));
        }
        static SerpentResult Decrypt(const std::string &ciphertext, const std::string &key, const std::string &iv)
        {
            Serpent cipher;
            return SerpentResult(cipher.decryptCBC(ciphertext, key, iv));
        }
    };
    struct CFB
    {
        static SerpentResult Encrypt(const std::string &plaintext, const std::string &key, const std::string &iv)
        {
            Serpent cipher;
            return SerpentResult(cipher.encryptCFB(plaintext, key, iv));
        }
        static SerpentResult Decrypt(const std::string &ciphertext, const std::string &key, const std::string &iv)
        {
            Serpent cipher;
            return SerpentResult(cipher.decryptCFB(ciphertext, key, iv));
        }
    };
    struct OFB
    {
        static SerpentResult Encrypt(const std::string &plaintext, const std::string &key, const std::string &iv)
        {
            Serpent cipher;
            return SerpentResult(cipher.encryptOFB(plaintext, key, iv));
        }
        static SerpentResult Decrypt(const std::string &ciphertext, const std::string &key, const std::string &iv)
        {
            Serpent cipher;
            return SerpentResult(cipher.decryptOFB(ciphertext, key, iv));
        }
    };
    struct CTR
    {
        static SerpentResult Encrypt(const std::string &plaintext, const std::string &key, const std::string &nonce)
        {
            Serpent cipher;
            return SerpentResult(cipher.encryptCTR(plaintext, key, nonce));
        }
        static SerpentResult Decrypt(const std::string &ciphertext, const std::string &key, const std::string &nonce)
        {
            Serpent cipher;
            return SerpentResult(cipher.decryptCTR(ciphertext, key, nonce));
        }
    };

    // ========== (Retain all original public/member functions for compatibility) ====

    template <typename... Args>
    __attr_nodiscard __attr_hot SerpentResult encrypt(const std::string &plaintext, const std::string &key, Args &&...args) const __const_noexcept
    {
        return SerpentResult(Policy::encrypt(*this, plaintext, key, std::forward<Args>(args)...));
    }
    template <typename... Args>
    __attr_nodiscard __attr_hot SerpentResult decrypt(const std::string &ciphertext, const std::string &key, Args &&...args) const __const_noexcept
    {
        return SerpentResult(Policy::decrypt(*this, ciphertext, key, std::forward<Args>(args)...));
    }

  private:
    std::string encryptBlock(const std::string &plaintext, const std::string &key) const __const_noexcept
    {
        if (unlikely(plaintext.size() != BlockSize))
            serpent_detail::fail("Serpent: encryptBlock: Plaintext must be 16 bytes.");
        if (unlikely(key.size() != KeySize))
            serpent_detail::fail("Serpent: encryptBlock: Key must match enum size.");
        std::string output(BlockSize, '\0');
        encryptBitslice(reinterpret_cast<const uchar *>(plaintext.data()), reinterpret_cast<const uchar *>(key.data()), reinterpret_cast<uchar *>(&output[0]));
        return output;
    }
    std::string decryptBlock(const std::string &ciphertext, const std::string &key) const __const_noexcept
    {
        if (unlikely(ciphertext.size() != BlockSize))
            serpent_detail::fail("Serpent: decryptBlock: Ciphertext must be 16 bytes.");
        if (unlikely(key.size() != KeySize))
            serpent_detail::fail("Serpent: decryptBlock: Key must match enum size.");
        std::string output(BlockSize, '\0');
        decryptBitslice(reinterpret_cast<const uchar *>(ciphertext.data()), reinterpret_cast<const uchar *>(key.data()), reinterpret_cast<uchar *>(&output[0]));
        return output;
    }
    std::string encryptECB(const std::string &plaintext, const std::string &key) const __const_noexcept
    {
        std::string padded = pkcs7Pad(plaintext);
        std::string ciphertext;
        ciphertext.reserve(padded.size());
        for (size_t i = 0; i < padded.size(); i += BlockSize)
            ciphertext += encryptBlock(padded.substr(i, BlockSize), key);
        return ciphertext;
    }
    std::string decryptECB(const std::string &ciphertext, const std::string &key) const __const_noexcept
    {
        if (unlikely(ciphertext.empty() || (ciphertext.size() % BlockSize) != 0))
            serpent_detail::fail("Serpent: decryptECB: Ciphertext size must be a positive multiple of 16 bytes.");
        std::string padded;
        padded.reserve(ciphertext.size());
        for (size_t i = 0; i < ciphertext.size(); i += BlockSize)
            padded += decryptBlock(ciphertext.substr(i, BlockSize), key);
        return pkcs7Unpad(padded);
    }
    std::string encryptCBC(const std::string &plaintext, const std::string &key, const std::string &iv) const __const_noexcept
    {
        if (unlikely(iv.size() != BlockSize))
            serpent_detail::fail("Serpent: encryptCBC: IV must be 16 bytes.");
        std::string padded = pkcs7Pad(plaintext);
        std::string ciphertext;
        ciphertext.reserve(padded.size());
        std::string prev = iv;
        for (size_t i = 0; i < padded.size(); i += BlockSize)
        {
            std::string block = padded.substr(i, BlockSize);
            std::string xored = xorStrings(block, prev);
            std::string enc = encryptBlock(xored, key);
            ciphertext += enc;
            prev = enc;
        }
        return ciphertext;
    }
    std::string decryptCBC(const std::string &ciphertext, const std::string &key, const std::string &iv) const __const_noexcept
    {
        if (unlikely(iv.size() != BlockSize))
            serpent_detail::fail("Serpent: decryptCBC: IV must be 16 bytes.");
        if (unlikely(ciphertext.empty() || (ciphertext.size() % BlockSize) != 0))
            serpent_detail::fail("Serpent: decryptCBC: Ciphertext size must be a positive multiple of 16 bytes.");
        std::string padded;
        padded.reserve(ciphertext.size());
        std::string prev = iv;
        for (size_t i = 0; i < ciphertext.size(); i += BlockSize)
        {
            std::string block = ciphertext.substr(i, BlockSize);
            std::string dec = decryptBlock(block, key);
            padded += xorStrings(dec, prev);
            prev = block;
        }
        return pkcs7Unpad(padded);
    }
    std::string encryptCFB(const std::string &plaintext, const std::string &key, const std::string &iv) const __const_noexcept
    {
        if (unlikely(iv.size() != BlockSize))
            serpent_detail::fail("Serpent: encryptCFB: IV must be 16 bytes.");
        std::string ciphertext;
        ciphertext.reserve(((plaintext.size() + BlockSize - 1) / BlockSize) * BlockSize);
        std::string prev = iv;
        for (size_t i = 0; i < plaintext.size(); i += BlockSize)
        {
            std::string block = plaintext.substr(i, BlockSize);
            std::string enc = encryptBlock(prev, key);
            std::string out(BlockSize, 0);
            for (size_t j = 0; j < BlockSize; ++j)
                out[j] = (j < block.size()) ? (block[j] ^ enc[j]) : enc[j];
            ciphertext += out.substr(0, block.size());
            prev = out;
        }
        return ciphertext;
    }
    std::string decryptCFB(const std::string &ciphertext, const std::string &key, const std::string &iv) const __const_noexcept
    {
        if (unlikely(iv.size() != BlockSize))
            serpent_detail::fail("Serpent: decryptCFB: IV must be 16 bytes.");
        std::string plaintext;
        plaintext.reserve(ciphertext.size());
        std::string prev = iv;
        for (size_t i = 0; i < ciphertext.size(); i += BlockSize)
        {
            std::string block = ciphertext.substr(i, BlockSize);
            std::string enc = encryptBlock(prev, key);
            std::string out(BlockSize, 0);
            for (size_t j = 0; j < block.size(); ++j)
                out[j] = block[j] ^ enc[j];
            plaintext += out.substr(0, block.size());
            prev = block + std::string(BlockSize - block.size(), '\0');
        }
        return plaintext;
    }
    std::string encryptOFB(const std::string &plaintext, const std::string &key, const std::string &iv) const __const_noexcept
    {
        if (unlikely(iv.size() != BlockSize))
            serpent_detail::fail("Serpent: encryptOFB: IV must be 16 bytes.");
        std::string ciphertext;
        ciphertext.reserve(plaintext.size());
        std::string ofb = iv;
        for (size_t i = 0; i < plaintext.size(); i += BlockSize)
        {
            ofb = encryptBlock(ofb, key);
            std::string block = plaintext.substr(i, BlockSize);
            std::string out(BlockSize, 0);
            for (size_t j = 0; j < block.size(); ++j)
                out[j] = block[j] ^ ofb[j];
            ciphertext += out.substr(0, block.size());
        }
        return ciphertext;
    }
    std::string decryptOFB(const std::string &ciphertext, const std::string &key, const std::string &iv) const __const_noexcept
    {
        return encryptOFB(ciphertext, key, iv);
    }
    std::string encryptCTR(const std::string &plaintext, const std::string &key, const std::string &nonce) const __const_noexcept
    {
        if (unlikely(nonce.size() != BlockSize))
            serpent_detail::fail("Serpent: encryptCTR: Nonce must be 16 bytes.");
        std::string ciphertext;
        ciphertext.reserve(plaintext.size());
        std::string counter = nonce;
        for (size_t i = 0; i < plaintext.size(); i += BlockSize)
        {
            std::string keystream = encryptBlock(counter, key);
            std::string block = plaintext.substr(i, BlockSize);
            std::string out(BlockSize, 0);
            for (size_t j = 0; j < block.size(); ++j)
                out[j] = block[j] ^ keystream[j];
            ciphertext += out.substr(0, block.size());
            incrementCounter(counter);
        }
        return ciphertext;
    }
    std::string decryptCTR(const std::string &ciphertext, const std::string &key, const std::string &nonce) const __const_noexcept
    {
        return encryptCTR(ciphertext, key, nonce);
    }

    std::string pkcs7Pad(const std::string &data) const __noexcept
    {
        size_t padLen = BlockSize - (data.size() % BlockSize);
        if (padLen == 0)
            padLen = BlockSize;
        std::string padded = data;
        padded.append(padLen, static_cast<char>(padLen));
        return padded;
    }
    std::string pkcs7Unpad(const std::string &data) const
    {
        if (unlikely(data.empty() || data.size() % BlockSize != 0))
            serpent_detail::fail("Serpent: pkcs7Unpad: Invalid padding size.");
        uchar padLen = static_cast<uchar>(data.back());
        if (unlikely(padLen == 0 || padLen > BlockSize))
            serpent_detail::fail("Serpent: pkcs7Unpad: Invalid padding value.");
        for (size_t i = data.size() - padLen; i < data.size(); ++i)
        {
            if (unlikely(static_cast<uchar>(data[i]) != padLen))
                serpent_detail::fail("Serpent: pkcs7Unpad: Invalid padding content.");
        }
        return data.substr(0, data.size() - padLen);
    }
    static std::string xorStrings(const std::string &a, const std::string &b) __noexcept
    {
        if (unlikely(a.size() != b.size()))
            serpent_detail::fail("Serpent: xorStrings: Inputs must have equal size.");
        std::string out(a.size(), '\0');
        for (size_t i = 0; i < a.size(); ++i)
            out[i] = a[i] ^ b[i];
        return out;
    }
    static void incrementCounter(std::string &counter) __noexcept
    {
        for (int i = BlockSize - 1; i >= 0; --i)
        {
            uint8_t &b = reinterpret_cast<uint8_t &>(counter[i]);
            if (++b != 0)
                break;
        }
    }

    void encryptBitslice(const uchar *plaintext, const uchar *key, uchar *output) const __noexcept
    {
        SubKeys subkeys{};
        generateKeySchedule(subkeys, key);

        Block state = {};
        std::memcpy(state.data(), plaintext, BlockSize);

        for (size_t round = 0; round < Rounds; ++round)
        {
            xorBlock(state, subkeys[round]);
            applySBox(state, round % 8);
            if (round < Rounds - 1)
                linearTransform(state);
            else
                xorBlock(state, subkeys[Rounds]);
        }
        std::memcpy(output, state.data(), BlockSize);
    }
    void decryptBitslice(const uchar *ciphertext, const uchar *key, uchar *output) const __noexcept
    {
        SubKeys subkeys{};
        generateKeySchedule(subkeys, key);

        Block state = {};
        std::memcpy(state.data(), ciphertext, BlockSize);

        for (int round = Rounds - 1; round >= 0; --round)
        {
            if (round < static_cast<int>(Rounds) - 1)
                inverseLinearTransform(state);
            else
                xorBlock(state, subkeys[Rounds]);
            inverseSBox(state, round % 8);
            xorBlock(state, subkeys[round]);
        }
        std::memcpy(output, state.data(), BlockSize);
    }

    static constexpr uint phi = 0x9e3779b9;

    void applySBox(Block &state, int sboxIdx) const __noexcept
    {
        Block newState = {};
        for (int bit = 0; bit < 32; ++bit)
        {
            uint input = ((state[0] >> bit) & 1) << 0 | ((state[1] >> bit) & 1) << 1 | ((state[2] >> bit) & 1) << 2 | ((state[3] >> bit) & 1) << 3;
            uint output = SBox[sboxIdx][input];
            for (int w = 0; w < 4; ++w)
                newState[w] |= ((output >> w) & 1) << bit;
        }
        state = newState;
    }
    void inverseSBox(Block &state, int sboxIdx) const __noexcept
    {
        Block newState = {};
        for (int bit = 0; bit < 32; ++bit)
        {
            uint input = ((state[0] >> bit) & 1) << 0 | ((state[1] >> bit) & 1) << 1 | ((state[2] >> bit) & 1) << 2 | ((state[3] >> bit) & 1) << 3;
            uint output = SBoxInverse[sboxIdx][input];
            for (int w = 0; w < 4; ++w)
                newState[w] |= ((output >> w) & 1) << bit;
        }
        state = newState;
    }
    void linearTransform(Block &state) const __noexcept
    {
        state[1] = rotl(state[1] ^ rotl(state[0], 13) ^ rotl(state[2], 3), 1);
        state[3] = rotl(state[3] ^ rotl(state[2], 3) ^ (rotl(state[0], 13) << 3), 7);
        state[0] = rotl(rotl(state[0], 13) ^ state[1] ^ state[3], 5);
        state[2] = rotl(rotl(state[2], 3) ^ state[3] ^ (state[1] << 7), 22);
    }
    void inverseLinearTransform(Block &state) const __noexcept
    {
        state[2] = rotl(state[2], 10) ^ state[3] ^ (state[1] << 7);
        state[0] = rotl(state[0], 27) ^ state[1] ^ state[3];
        state[3] = rotl(state[3], 25);
        state[1] = rotl(state[1], 31);
        state[3] = state[3] ^ state[2] ^ (state[0] << 3);
        state[1] = state[1] ^ state[0] ^ state[2];
        state[2] = rotl(state[2], 29);
        state[0] = rotl(state[0], 19);
    }

    void generateKeySchedule(SubKeys &subkeys, const uchar *key) const __noexcept
    {
        std::array<uint, 8> keySplit{};
        std::array<uint, 140> interKey{};
        prepareKey(keySplit, key);
        expandKey(interKey, keySplit);
        generateSubkeys(subkeys, interKey);
    }
    void prepareKey(std::array<uint, 8> &keySplit, const uchar *key) const __noexcept
    {
        std::array<uchar, 32> paddedKey = {};
        std::memset(paddedKey.data(), 0, 32);
        std::memcpy(paddedKey.data(), key, KeySize);
        if (KeySize < 32)
        {
            paddedKey[KeySize] = 0x01;
        }
        for (int i = 0; i < 8; ++i)
            keySplit[i] = *reinterpret_cast<const uint *>(&paddedKey[i * 4]);
    }
    void expandKey(std::array<uint, 140> &interKey, const std::array<uint, 8> &keySplit) const __noexcept
    {
        std::copy(keySplit.begin(), keySplit.end(), interKey.begin());
        for (int i = 8; i < 140; ++i)
            interKey[i] = rotl((interKey[i - 8] ^ interKey[i - 5] ^ interKey[i - 3] ^ interKey[i - 1] ^ phi ^ (i - 8)), 11);
    }
    void generateSubkeys(SubKeys &subkeys, const std::array<uint, 140> &interKey) const __noexcept
    {
        for (int i = 0; i <= static_cast<int>(Rounds); ++i)
        {
            int box = (Rounds + 3 - i) % 32;
            for (int j = 0; j < 32; ++j)
            {
                uint sboxOut = SBox[box % 8][((interKey[8 + 0 + (4 * i)] >> j) & 1) << 0 | ((interKey[8 + 1 + (4 * i)] >> j) & 1) << 1 |
                                             ((interKey[8 + 2 + (4 * i)] >> j) & 1) << 2 | ((interKey[8 + 3 + (4 * i)] >> j) & 1) << 3];
                for (int l = 0; l < 4; ++l)
                    subkeys[i][l] |= ((sboxOut >> l) & 1) << j;
            }
        }
    }
    static constexpr uint rotl(uint x, int p) __noexcept
    {
        return ((x << p) | (x >> (32 - p))) & 0xffffffffu;
    }
    static void xorBlock(Block &a, const Block &b) __noexcept
    {
        for (int i = 0; i < 4; ++i)
            a[i] ^= b[i];
    }
    static constexpr uint SBox[8][16] = {{3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12}, {15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4},
                                         {8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2}, {0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14},
                                         {1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13}, {15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1},
                                         {7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0}, {1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6}};
    static constexpr uint SBoxInverse[8][16] = {{13, 3, 11, 0, 10, 6, 5, 12, 1, 14, 4, 7, 15, 9, 8, 2}, {5, 8, 2, 14, 15, 6, 12, 3, 11, 4, 7, 9, 1, 13, 10, 0},
                                                {12, 9, 15, 4, 11, 14, 1, 2, 0, 3, 6, 13, 5, 8, 10, 7}, {0, 9, 10, 7, 11, 14, 6, 13, 3, 5, 12, 2, 4, 8, 15, 1},
                                                {5, 0, 8, 3, 10, 9, 7, 14, 2, 12, 11, 6, 4, 15, 13, 1}, {8, 15, 2, 9, 4, 1, 13, 14, 11, 6, 5, 3, 7, 12, 10, 0},
                                                {15, 10, 1, 13, 5, 3, 6, 0, 4, 9, 14, 7, 2, 12, 8, 11}, {3, 0, 6, 13, 9, 14, 15, 8, 5, 12, 11, 7, 10, 1, 4, 2}};

    // --- Mode Policies (for backwards compatibility with member encrypt()/decrypt()) ---
    template <typename C> struct ECB_Policy
    {
        static std::string encrypt(const C &cipher, const std::string &plaintext, const std::string &key)
        {
            return cipher.encryptECB(plaintext, key);
        }
        static std::string decrypt(const C &cipher, const std::string &ciphertext, const std::string &key)
        {
            return cipher.decryptECB(ciphertext, key);
        }
    };
    template <typename C> struct CBC_Policy
    {
        static std::string encrypt(const C &cipher, const std::string &plaintext, const std::string &key, const std::string &iv)
        {
            return cipher.encryptCBC(plaintext, key, iv);
        }
        static std::string decrypt(const C &cipher, const std::string &ciphertext, const std::string &key, const std::string &iv)
        {
            return cipher.decryptCBC(ciphertext, key, iv);
        }
    };
    template <typename C> struct CFB_Policy
    {
        static std::string encrypt(const C &cipher, const std::string &plaintext, const std::string &key, const std::string &iv)
        {
            return cipher.encryptCFB(plaintext, key, iv);
        }
        static std::string decrypt(const C &cipher, const std::string &ciphertext, const std::string &key, const std::string &iv)
        {
            return cipher.decryptCFB(ciphertext, key, iv);
        }
    };
    template <typename C> struct OFB_Policy
    {
        static std::string encrypt(const C &cipher, const std::string &plaintext, const std::string &key, const std::string &iv)
        {
            return cipher.encryptOFB(plaintext, key, iv);
        }
        static std::string decrypt(const C &cipher, const std::string &ciphertext, const std::string &key, const std::string &iv)
        {
            return cipher.decryptOFB(ciphertext, key, iv);
        }
    };
    template <typename C> struct CTR_Policy
    {
        static std::string encrypt(const C &cipher, const std::string &plaintext, const std::string &key, const std::string &nonce)
        {
            return cipher.encryptCTR(plaintext, key, nonce);
        }
        static std::string decrypt(const C &cipher, const std::string &ciphertext, const std::string &key, const std::string &nonce)
        {
            return cipher.decryptCTR(ciphertext, key, nonce);
        }
    };

    using Policy = ECB_Policy<Serpent>; // Default to ECB in member .encrypt/.decrypt
};
