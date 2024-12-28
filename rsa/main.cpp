#include <iostream>
#include <fstream>
#include <chrono>
#include <sys/resource.h> // Để thống kê RAM và CPU
#include <unistd.h>       // Để lấy thông tin hệ thống
#include "rsa_lib.h"      // Include header

// Hàm lấy thông tin bộ nhớ tiêu tốn
void logMemoryUsage(const std::string &stage) {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        std::cout << "=== Thống kê tài nguyên tại " << stage << " ===\n";
        std::cout << "Bộ nhớ RAM tiêu tốn: " << usage.ru_maxrss / 1024.0 << " MB\n";
        std::cout << "Thời gian CPU (user): " << usage.ru_utime.tv_sec << "s " << usage.ru_utime.tv_usec / 1000 << "ms\n";
        std::cout << "Thời gian CPU (system): " << usage.ru_stime.tv_sec << "s " << usage.ru_stime.tv_usec / 1000 << "ms\n\n";
    } else {
        std::cerr << "Không thể lấy thông tin tài nguyên!\n";
    }
}

int main() {
    int keyBitSize;
    bool verbose = true; // In thông tin chi tiết
    bool debug = false;  // Tắt debug để tăng tốc

    // Hỏi người dùng nhập độ dài khóa
    std::cout << "Nhập độ dài khóa RSA (ví dụ: 2048, 4096, 8192): ";
    std::cin >> keyBitSize;

    std::cout << "=== SINH KHOA RSA (" << keyBitSize << " bits) ===\n";

    PublicKey pub;
    PrivateKey priv;

    try {
        // Đo thời gian bắt đầu tạo khóa
        auto startKeyGen = std::chrono::high_resolution_clock::now();

        // Tạo khóa RSA
        CreateRSAKey(keyBitSize, verbose, debug, pub, priv);

        // Đo thời gian kết thúc tạo khóa
        auto endKeyGen = std::chrono::high_resolution_clock::now();
        auto keyGenDuration = std::chrono::duration_cast<std::chrono::milliseconds>(endKeyGen - startKeyGen);

        // Lưu khóa vào file
        SaveKeys("mykey", pub, priv);
        std::cout << "\nĐã lưu khóa công khai vào [mykey.pub]\n"
                  << "Đã lưu khóa bí mật  vào [mykey.key]\n\n";
        std::cout << "Thời gian tạo khóa: " << keyGenDuration.count() << " ms\n\n";

        // Thống kê tài nguyên sau khi tạo khóa
        logMemoryUsage("tạo khóa");
    } catch (const std::exception &ex) {
        std::cerr << "Lỗi khi sinh khóa: " << ex.what() << std::endl;
        return 1;
    }

    // BƯỚC 2: Mã hóa file
    std::string sourceFile = "plaintext.txt";   // file gốc
    std::string cipherFile = "cipher.dat";      // file mã hóa
    std::string pubKeyPath = "mykey.pub";       // khóa công khai đã lưu

    std::cout << "=== MA HOA FILE ===\n";

    try {
        // Đo thời gian bắt đầu mã hóa
        auto startEncrypt = std::chrono::high_resolution_clock::now();

        if (EncryptFile(sourceFile, cipherFile, pubKeyPath) == 0) {
            // Đo thời gian kết thúc mã hóa
            auto endEncrypt = std::chrono::high_resolution_clock::now();
            auto encryptDuration = std::chrono::duration_cast<std::chrono::milliseconds>(endEncrypt - startEncrypt);

            std::cout << "Đã mã hóa file [" << sourceFile << "] => [" << cipherFile << "]\n";
            std::cout << "Thời gian mã hóa: " << encryptDuration.count() << " ms\n\n";

            // Thống kê tài nguyên sau khi mã hóa
            logMemoryUsage("mã hóa");
        } else {
            std::cerr << "EncryptFile thất bại!\n";
            return 1;
        }
    } catch (const std::exception &ex) {
        std::cerr << "Lỗi khi mã hóa: " << ex.what() << std::endl;
        return 1;
    }

    // BƯỚC 3: Giải mã file
    std::string destFile = "plaintext_dec.txt"; // file sau khi giải mã
    std::string privKeyPath = "mykey.key";      // khóa bí mật đã lưu

    std::cout << "=== GIAI MA FILE ===\n";

    try {
        // Đo thời gian bắt đầu giải mã
        auto startDecrypt = std::chrono::high_resolution_clock::now();

        if (DecryptFile(cipherFile, destFile, privKeyPath) == 0) {
            // Đo thời gian kết thúc giải mã
            auto endDecrypt = std::chrono::high_resolution_clock::now();
            auto decryptDuration = std::chrono::duration_cast<std::chrono::milliseconds>(endDecrypt - startDecrypt);

            std::cout << "Đã giải mã file [" << cipherFile << "] => [" << destFile << "]\n";
            std::cout << "Thời gian giải mã: " << decryptDuration.count() << " ms\n\n";

            // Thống kê tài nguyên sau khi giải mã
            logMemoryUsage("giải mã");
        } else {
            std::cerr << "DecryptFile thất bại!\n";
            return 1;
        }
    } catch (const std::exception &ex) {
        std::cerr << "Lỗi khi giải mã: " << ex.what() << std::endl;
        return 1;
    }

    // Kiểm tra nội dung file
    std::ifstream fin1(sourceFile, std::ios::binary);
    std::ifstream fin2(destFile, std::ios::binary);

    if (fin1 && fin2) {
        std::string s1((std::istreambuf_iterator<char>(fin1)), std::istreambuf_iterator<char>());
        std::string s2((std::istreambuf_iterator<char>(fin2)), std::istreambuf_iterator<char>());

        if (s1 == s2) {
            std::cout << "Nội dung file giải mã giống với file gốc!\n";
        } else {
            std::cout << "File giải mã KHÔNG khớp nội dung file gốc.\n";
        }
    }

    return 0;
}
