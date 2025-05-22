#include "serpent.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>

// ANSI color codes
#define CLR_RESET   "\033[0m"
#define CLR_GREEN   "\033[32m"
#define CLR_RED     "\033[31m"
#define CLR_BLUE    "\033[34m"
#define CLR_YELLOW  "\033[33m"
#define CLR_BOLD    "\033[1m"

using serpent_util::toHex;

// Utility: Print line with color and delay
void print_slow(const std::string& line, const char* color = CLR_RESET, int millis = 30) {
    std::cout << color << line << CLR_RESET << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(millis));
}

// Utility: Print a separator line
void print_separator(const std::string& label = "", const char* color = CLR_YELLOW, int millis = 60) {
    std::string sep = std::string(4, '-') + " " + label + " " + std::string(40, '-');
    print_slow(sep, color, millis);
}

// Main test function
void test_mode(const std::string& mode_name, const std::string& original_message, size_t& counter, size_t& total_operations) {
    std::vector<KEY_SIZE> key_sizes = { KEY_SIZE::BITS_128, KEY_SIZE::BITS_192, KEY_SIZE::BITS_256 };

    for (const auto& key_size : key_sizes) {
        print_separator("Key Size: " + std::to_string((int)key_size * 8) + " bits", CLR_YELLOW, 90);

        // Shrinking: from 50 bytes down to 1
        for (int len = 50; len >= 1; --len) {
            std::string msg = original_message.substr(0, len);
            std::string key = KeyIVGenerator::generateKey(key_size);
            std::string iv  = KeyIVGenerator::generateIV(16);

            std::string enc, dec;
            bool ok = false;
            try {
                if (mode_name == "ECB") {
                    if (key_size == KEY_SIZE::BITS_128) {
                        Serpent<ECB_Mode, KEY_SIZE::BITS_128> serpent;
                        enc = serpent.encrypt(msg, key).asString();
                        dec = serpent.decrypt(enc, key).asString();
                    } else if (key_size == KEY_SIZE::BITS_192) {
                        Serpent<ECB_Mode, KEY_SIZE::BITS_192> serpent;
                        enc = serpent.encrypt(msg, key).asString();
                        dec = serpent.decrypt(enc, key).asString();
                    } else {
                        Serpent<ECB_Mode, KEY_SIZE::BITS_256> serpent;
                        enc = serpent.encrypt(msg, key).asString();
                        dec = serpent.decrypt(enc, key).asString();
                    }
                } else if (mode_name == "CBC") {
                    if (key_size == KEY_SIZE::BITS_128) {
                        Serpent<CBC_Mode, KEY_SIZE::BITS_128> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    } else if (key_size == KEY_SIZE::BITS_192) {
                        Serpent<CBC_Mode, KEY_SIZE::BITS_192> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    } else {
                        Serpent<CBC_Mode, KEY_SIZE::BITS_256> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    }
                } else if (mode_name == "CFB") {
                    if (key_size == KEY_SIZE::BITS_128) {
                        Serpent<CFB_Mode, KEY_SIZE::BITS_128> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    } else if (key_size == KEY_SIZE::BITS_192) {
                        Serpent<CFB_Mode, KEY_SIZE::BITS_192> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    } else {
                        Serpent<CFB_Mode, KEY_SIZE::BITS_256> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    }
                } else if (mode_name == "OFB") {
                    if (key_size == KEY_SIZE::BITS_128) {
                        Serpent<OFB_Mode, KEY_SIZE::BITS_128> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    } else if (key_size == KEY_SIZE::BITS_192) {
                        Serpent<OFB_Mode, KEY_SIZE::BITS_192> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    } else {
                        Serpent<OFB_Mode, KEY_SIZE::BITS_256> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    }
                } else if (mode_name == "CTR") {
                    if (key_size == KEY_SIZE::BITS_128) {
                        Serpent<CTR_Mode, KEY_SIZE::BITS_128> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    } else if (key_size == KEY_SIZE::BITS_192) {
                        Serpent<CTR_Mode, KEY_SIZE::BITS_192> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    } else {
                        Serpent<CTR_Mode, KEY_SIZE::BITS_256> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    }
                }
                ok = (dec == msg);
            } catch (...) {
                ok = false;
            }

            print_slow("    Message (" + std::to_string(len) + "): " + toHex(msg), CLR_RESET, 100);
            print_slow("    Key: " + toHex(key) + " | Key size: " + std::to_string((int)key_size * 8) + " bits", CLR_YELLOW, 80);
            print_slow("    IV/Nonce: " + toHex(iv), CLR_YELLOW, 80);
            print_slow("    Ciphertext: " + toHex(enc), CLR_BLUE, 80);
            print_slow("    Decrypted: " + toHex(dec), (ok ? CLR_GREEN : CLR_RED), 80);
            print_slow("    Status: " + std::string(ok ? "Success" : "FAIL"), (ok ? CLR_GREEN : CLR_RED), 60);
            std::this_thread::sleep_for(std::chrono::milliseconds(70));

            ++total_operations;
            if (ok) ++counter;
        }

        // Growing: from 1 byte to 50
        for (int len = 1; len <= 50; ++len) {
            std::string msg = original_message.substr(0, len);
            std::string key = KeyIVGenerator::generateKey(key_size);
            std::string iv  = KeyIVGenerator::generateIV(16);

            std::string enc, dec;
            bool ok = false;
            try {
                if (mode_name == "ECB") {
                    if (key_size == KEY_SIZE::BITS_128) {
                        Serpent<ECB_Mode, KEY_SIZE::BITS_128> serpent;
                        enc = serpent.encrypt(msg, key).asString();
                        dec = serpent.decrypt(enc, key).asString();
                    } else if (key_size == KEY_SIZE::BITS_192) {
                        Serpent<ECB_Mode, KEY_SIZE::BITS_192> serpent;
                        enc = serpent.encrypt(msg, key).asString();
                        dec = serpent.decrypt(enc, key).asString();
                    } else {
                        Serpent<ECB_Mode, KEY_SIZE::BITS_256> serpent;
                        enc = serpent.encrypt(msg, key).asString();
                        dec = serpent.decrypt(enc, key).asString();
                    }
                } else if (mode_name == "CBC") {
                    if (key_size == KEY_SIZE::BITS_128) {
                        Serpent<CBC_Mode, KEY_SIZE::BITS_128> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    } else if (key_size == KEY_SIZE::BITS_192) {
                        Serpent<CBC_Mode, KEY_SIZE::BITS_192> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    } else {
                        Serpent<CBC_Mode, KEY_SIZE::BITS_256> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    }
                } else if (mode_name == "CFB") {
                    if (key_size == KEY_SIZE::BITS_128) {
                        Serpent<CFB_Mode, KEY_SIZE::BITS_128> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    } else if (key_size == KEY_SIZE::BITS_192) {
                        Serpent<CFB_Mode, KEY_SIZE::BITS_192> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    } else {
                        Serpent<CFB_Mode, KEY_SIZE::BITS_256> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    }
                } else if (mode_name == "OFB") {
                    if (key_size == KEY_SIZE::BITS_128) {
                        Serpent<OFB_Mode, KEY_SIZE::BITS_128> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    } else if (key_size == KEY_SIZE::BITS_192) {
                        Serpent<OFB_Mode, KEY_SIZE::BITS_192> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    } else {
                        Serpent<OFB_Mode, KEY_SIZE::BITS_256> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    }
                } else if (mode_name == "CTR") {
                    if (key_size == KEY_SIZE::BITS_128) {
                        Serpent<CTR_Mode, KEY_SIZE::BITS_128> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    } else if (key_size == KEY_SIZE::BITS_192) {
                        Serpent<CTR_Mode, KEY_SIZE::BITS_192> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    } else {
                        Serpent<CTR_Mode, KEY_SIZE::BITS_256> serpent;
                        enc = serpent.encrypt(msg, key, iv).asString();
                        dec = serpent.decrypt(enc, key, iv).asString();
                    }
                }
                ok = (dec == msg);
            } catch (...) {
                ok = false;
            }

            print_slow("    Message (" + std::to_string(len) + "): " + toHex(msg), CLR_RESET, 100);
            print_slow("    Key: " + toHex(key) + " | Key size: " + std::to_string((int)key_size * 8) + " bits", CLR_YELLOW, 80);
            print_slow("    IV/Nonce: " + toHex(iv), CLR_YELLOW, 80);
            print_slow("    Ciphertext: " + toHex(enc), CLR_BLUE, 80);
            print_slow("    Decrypted: " + toHex(dec), (ok ? CLR_GREEN : CLR_RED), 80);
            print_slow("    Status: " + std::string(ok ? "Success" : "FAIL"), (ok ? CLR_GREEN : CLR_RED), 60);
            std::this_thread::sleep_for(std::chrono::milliseconds(70));

            ++total_operations;
            if (ok) ++counter;
        }
    }
}

int main() {
    std::string original_message = "This is a 50-byte string for SERPENT testing!!!***";
    original_message.resize(50); // Ensure it's exactly 50 bytes

    std::vector<std::string> modes = {"ECB", "CBC", "CFB", "OFB", "CTR"};
    size_t counter = 0;
    size_t total_operations = 0;

    for (const auto& mode_name : modes) {
        print_separator("Mode: " + mode_name, CLR_BLUE, 100);
        test_mode(mode_name, original_message, counter, total_operations);
    }

    print_separator("Summary", CLR_BOLD, 200);
    print_slow("Total successful encrypt+decrypt operations: " + std::to_string(counter) + "/" + std::to_string(total_operations), CLR_BOLD, 200);
    return 0;
}
