#include "serpent.hpp"
#include <iostream>

int main() {
    using serpent256 = Serpent<KEY_SIZE::BITS_256>;
    std::string message = "The quick brown fox jumps over the lazy dog";

    // Generate a random key and IV/nonce for demonstration
    std::string key = KeyIVGenerator::generateKey(KEY_SIZE::BITS_256);
    std::string iv  = KeyIVGenerator::generateIV();
    std::string nonce = KeyIVGenerator::generateIV(); // For CTR

    // --- ECB Mode ---
    auto ecb_ct = serpent256::ECB::Encrypt(message, key);
    auto ecb_pt = serpent256::ECB::Decrypt(ecb_ct.asString(), key);
    std::cout << "[ECB] Encrypted (hex): " << ecb_ct.toHex().asString() << "\n";
    std::cout << "[ECB] Decrypted: " << ecb_pt.asString() << "\n\n";

    // --- CBC Mode ---
    auto cbc_ct = serpent256::CBC::Encrypt(message, key, iv);
    auto cbc_pt = serpent256::CBC::Decrypt(cbc_ct.asString(), key, iv);
    std::cout << "[CBC] Encrypted (hex): " << cbc_ct.toHex().asString() << "\n";
    std::cout << "[CBC] Decrypted: " << cbc_pt.asString() << "\n\n";

    // --- CFB Mode ---
    auto cfb_ct = serpent256::CFB::Encrypt(message, key, iv);
    auto cfb_pt = serpent256::CFB::Decrypt(cfb_ct.asString(), key, iv);
    std::cout << "[CFB] Encrypted (hex): " << cfb_ct.toHex().asString() << "\n";
    std::cout << "[CFB] Decrypted: " << cfb_pt.asString() << "\n\n";

    // --- OFB Mode ---
    auto ofb_ct = serpent256::OFB::Encrypt(message, key, iv);
    auto ofb_pt = serpent256::OFB::Decrypt(ofb_ct.asString(), key, iv);
    std::cout << "[OFB] Encrypted (hex): " << ofb_ct.toHex().asString() << "\n";
    std::cout << "[OFB] Decrypted: " << ofb_pt.asString() << "\n\n";

    // --- CTR Mode ---
    auto ctr_ct = serpent256::CTR::Encrypt(message, key, nonce);
    auto ctr_pt = serpent256::CTR::Decrypt(ctr_ct.asString(), key, nonce);
    std::cout << "[CTR] Encrypted (hex): " << ctr_ct.toHex().asString() << "\n";
    std::cout << "[CTR] Decrypted: " << ctr_pt.asString() << "\n\n";

    return 0;
}
