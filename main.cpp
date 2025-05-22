#include "serpent.hpp" // include this anaconda...
#include <iostream>

int main() {
    // Example key and IV generation
    std::string key = KeyIVGenerator::generateKey(KEY_SIZE::BITS_256);
    std::string iv = KeyIVGenerator::generateIV(); // for CBC/CFB/OFB/CTR modes

    // Example plaintext
    std::string plaintext = "Hello, world! This is a Serpent test.";

    // Instantiate Serpent (default: ECB mode, 256-bit key)
    Serpent<> serpent;

    // Encrypt in ECB mode, get hex string
    auto encryptedHex = serpent.encrypt(plaintext, key).toHex().asString();
    std::cout << "Encrypted (hex): " << encryptedHex << std::endl;

    // Convert hex back to bytes and decrypt
    auto decrypted = serpent.decrypt(SerpentResult(encryptedHex).fromHex().asString(), key).toString().asString();
    std::cout << "Decrypted: " << decrypted << std::endl;

    // Encrypt in base64 and get as vector
    auto encryptedBase64Vec = serpent.encrypt(plaintext, key).toBase64().toVector().asVector();
    std::cout << "Encrypted (base64, as vector): ";
    for (uint8_t b : encryptedBase64Vec) std::cout << b;
    std::cout << std::endl;

    // Example with CBC mode (chaining works the same)
    Serpent<CBC_Mode> serpent_cbc;
    auto encryptedCBCBase64 = serpent_cbc.encrypt(plaintext, key, iv).toBase64().asString();
    std::cout << "Encrypted CBC (base64): " << encryptedCBCBase64 << std::endl;

    // To decrypt CBC with base64 input
    auto decryptedCBC = serpent_cbc.decrypt(SerpentResult(encryptedCBCBase64).fromBase64().asString(), key, iv).toString().asString();
    std::cout << "Decrypted CBC: " << decryptedCBC << std::endl;

    return 0;
}
