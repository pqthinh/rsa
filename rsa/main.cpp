// main.cpp
#include "rsa_lib.h"
#include <iostream>
#include <limits>
#include <chrono>    // Thêm thư viện chrono để đo thời gian
#include <fstream>   // Thêm thư viện fstream để sử dụng ifstream và ofstream

int main() {
    int keysize;
    std::cout << "Enter RSA key size (in bits, e.g., 2048): ";
    while (!(std::cin >> keysize) || keysize < 512 || keysize % 64 != 0) {
        std::cout << "Invalid input. Please enter a key size that is a multiple of 64 and at least 512 bits: ";
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }

    std::string keypath = "mykey";

    PublicKey pub;
    PrivateKey priv;

    try {
        // Đo thời gian tạo khóa
        auto start_keygen = std::chrono::high_resolution_clock::now();
        std::cout << "Generating RSA keys...\n";
        CreateRSAKey(keysize, true, false, pub, priv);
        auto end_keygen = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> duration_keygen = end_keygen - start_keygen;
        std::cout << "Time taken to generate keys: " << duration_keygen.count() << " seconds\n";

        // Đo thời gian lưu khóa
        auto start_save = std::chrono::high_resolution_clock::now();
        std::cout << "Saving keys to " << keypath << ".pub and " << keypath << ".key\n";
        if (SaveKeys(keypath, pub, priv) != 0) {
            std::cerr << "Failed to save keys.\n";
            return 1;
        }
        auto end_save = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> duration_save = end_save - start_save;
        std::cout << "Time taken to save keys: " << duration_save.count() << " seconds\n";

        std::cout << "Keys generated and saved successfully.\n";
    } catch (const std::exception &e) {
        std::cerr << "Error during key generation: " << e.what() << "\n";
        return 1;
    }

    // Đo thời gian mã hóa
    auto start_encrypt = std::chrono::high_resolution_clock::now();
    std::cout << "Encrypting plaintext.txt to ciphertext.bin using " << keypath << ".pub...\n";
    if (EncryptFile("plaintext.txt", "ciphertext.bin", keypath + ".pub") != 0) {
        std::cerr << "Encryption failed.\n";
        return 1;
    }
    auto end_encrypt = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration_encrypt = end_encrypt - start_encrypt;
    std::cout << "Encryption completed successfully.\n";
    std::cout << "Time taken to encrypt: " << duration_encrypt.count() << " seconds\n";

    // Đo thời gian giải mã
    auto start_decrypt = std::chrono::high_resolution_clock::now();
    std::cout << "Decrypting ciphertext.bin to decrypted.txt using " << keypath << ".key...\n";
    if (DecryptFile("ciphertext.bin", "decrypted.txt", keypath + ".key") != 0) {
        std::cerr << "Decryption failed.\n";
        return 1;
    }
    auto end_decrypt = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration_decrypt = end_decrypt - start_decrypt;
    std::cout << "Decryption completed successfully.\n";
    std::cout << "Time taken to decrypt: " << duration_decrypt.count() << " seconds\n";

    // Kiểm tra tính đúng đắn của giải mã
    std::cout << "Verifying decrypted.txt...\n";
    std::ifstream original("plaintext.txt", std::ios::binary);
    std::ifstream decrypted("decrypted.txt", std::ios::binary);

    if (!original) {
        std::cerr << "Cannot open plaintext.txt for verification.\n";
        return 1;
    }
    if (!decrypted) {
        std::cerr << "Cannot open decrypted.txt for verification.\n";
        return 1;
    }

    std::istreambuf_iterator<char> original_it(original);
    std::istreambuf_iterator<char> decrypted_it(decrypted);

    std::istreambuf_iterator<char> end;

    bool match = std::equal(original_it, end, decrypted_it);

    if (match) {
        std::cout << "Verification successful: decrypted.txt matches plaintext.txt\n";
    } else {
        std::cerr << "Verification failed: decrypted.txt does not match plaintext.txt\n";
    }

    return 0;
}
