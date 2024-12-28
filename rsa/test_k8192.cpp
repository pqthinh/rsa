#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include "rsa_lib.h"

/*
  Hàm này sẽ tạo cặp khóa RSA 8192 bit, 
  lưu vào file "k8192.pub" và "k8192.key".
*/
void TestCreateRSAKey8192() {
    std::cout << "=== TestCreateRSAKey8192 ===\n";
    PublicKey pub;
    PrivateKey priv;
    try {
        // Tạo khóa 8192 bit
        CreateRSAKey(8192, true, false, pub, priv);
        // Lưu
        SaveKeys("k8192", pub, priv);
        std::cout << "Đã lưu cặp khóa 8192 bit vào [k8192.pub] và [k8192.key]\n";
    }
    catch (const std::exception &ex) {
        std::cout << "Lỗi khi tạo khóa 8192 bit: " << ex.what() << std::endl;
    }
    std::cout << "========================================\n\n";
}

/*
  Sinh & kiểm tra khóa 8192 bit
  (Hoặc bạn có thể giữ nguyên nếu muốn test 256 bit).
*/
void TestKeySaveReload() {
    std::cout << "=== TestKeySaveReload (8192 bit) ===\n";
    PublicKey pub;
    PrivateKey priv;

    try {
        // Tạo cặp khóa 8192 bit
        CreateRSAKey(8192, false, false, pub, priv);
    } catch (const std::exception &ex) {
        std::cout << "Error creating keys: " << ex.what() << std::endl;
        return;
    }

    // Lưu thử với tên "test8192"
    if (SaveKeys("test8192", pub, priv) != 0) {
        std::cout << "Error saving keys\n";
        return;
    }

    std::cout << "public-nn:  " << pub.nn.get_str(16) << "\n";
    std::cout << "private-nn: " << priv.nn.get_str(16) << "\n";
    std::cout << "public-ee:  " << pub.ee.get_str(16) << "\n";
    std::cout << "private-dd: " << priv.dd.get_str(16) << "\n";

    // Đọc lại
    PublicKey pub2;
    PrivateKey priv2;
    if (GetKeys("test8192", pub2, priv2) != 0) {
        std::cout << "Error reading keys\n";
        return;
    }

    std::cout << "-------------------------------------------------------------------\n";
    std::cout << "public-nn:  " << pub2.nn.get_str(16) << "\n";
    std::cout << "private-nn: " << priv2.nn.get_str(16) << "\n";
    std::cout << "public-ee:  " << pub2.ee.get_str(16) << "\n";
    std::cout << "private-dd: " << priv2.dd.get_str(16) << "\n";

    // So sánh
    if (pub2.nn != pub.nn) {
        std::cout << "Error public key nn not equal\n";
        return;
    }
    if (pub2.ee != pub.ee) {
        std::cout << "Error public key ee not equal\n";
        return;
    }
    if (priv2.nn != priv.nn) {
        std::cout << "Error private key nn not equal\n";
        return;
    }
    if (priv2.dd != priv.dd) {
        std::cout << "Error private key dd not equal\n";
        return;
    }
    std::cout << "keys ok\n";
    std::cout << "========================================\n\n";
}

/*
  Test2: Tương tự code cũ, 
  test việc gọi GetNextPrime cho 1 số decimal lớn, đo thời gian.
*/
void Test2() {
    std::cout << "=== Test2 (GetNextPrime) ===\n";
    // n = NewDecimal(...)
    std::string dec_str = 
    "134525465745756822344523543563467456756734534535643455675678679880548658956787753245634575678978908790097943261452344467468789808790890706646523463456745845696789456734562465785697576894576345523465546785687689658465234524363567468764967365324564665456875664567458656787535635687456734654982763834563651763937";

    mpz_class n = NewDecimal(dec_str);
    std::cout << "Size (bits): " << mpz_sizeinbase(n.get_mpz_t(), 2) << "\n";

    auto t0 = std::chrono::high_resolution_clock::now();
    GetNextPrime(n, false, false);
    auto t1 = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    std::cout << "time=" << ms << " ms\n";
    std::cout << "prime=" << n.get_str() << "\n";
    std::cout << "========================================\n\n";
}

/*
  TestEncriptDecript2: 
  - Đọc khóa 'k8192' (thay k256), 
  - Vòng lặp vô hạn: random data => encrypt => decrypt => so sánh.
*/
void TestEncriptDecript2() {
    std::cout << "=== TestEncriptDecript2 ===\n";
    PublicKey pub;
    PrivateKey priv;
    if (GetKeys("k8192", pub, priv) != 0) {
        std::cout << "Error reading key: k8192\n";
        return;
    }

    int size = pub.GetRSAKeySize()/8 - 1;
    std::cout << "Load k8192 done. block size: " << size << " bytes\n";

    std::vector<unsigned char> list(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned short> dist(0, 255);

    long long nn = 0;
    while (true) {
        // random 1 block
        for (int i = 0; i < size; i++) {
            list[i] = (unsigned char)dist(gen);
        }

        std::vector<unsigned char> enc, dec;
        try {
            enc = pub.Encrypt(list, size+1);
            dec = priv.Decrypt(enc, size);
        } catch (const std::exception &ex) {
            std::cout << "Error: " << ex.what() << "\n";
            return;
        }

        if (dec.size() != list.size()) {
            std::cout << "Error: mismatch size\n";
            return;
        }
        for (size_t i = 0; i < list.size(); i++) {
            if (list[i] != dec[i]) {
                std::cout << "Error mismatch at " << i << "\n";
                return;
            }
        }
        nn++;
        if (nn % 1000 == 0) {
            std::cout << nn << " blocks tested.\n";
        }
    }
    // Vòng lặp vô hạn, nhấn Ctrl+C để dừng.
}

/*
  TestEncriptDecript:
  - Đọc khóa 'k8192',
  - Thử encrypt + decrypt 1 mảng 31 bytes,
  - Kiểm tra kết quả.
*/
void TestEncriptDecript() {
    std::cout << "=== TestEncriptDecript ===\n";
    PublicKey pub;
    PrivateKey priv;
    //"k8192" để dùng khóa 8192-bit
    if (GetKeys("k8192", pub, priv) != 0) {
        std::cout << "Error reading key: k8192\n";
        return;
    }

    int size = pub.GetRSAKeySize()/8 - 1;
    std::cout << "Load k8192 done. block size: " << size << " bytes\n";

    // Chuỗi 31 byte
    std::vector<unsigned char> list {
        15, 211, 218, 155, 207, 209, 212, 102, 241, 192,
        130, 92, 10, 92, 213, 236, 172, 190, 189, 213,
        116, 66, 8, 33, 132, 16, 66, 8, 33, 132, 16
    };
    std::cout << "list size = " << list.size() << " bytes\n";

    // Encrypt
    std::vector<unsigned char> enc;
    try {
        enc = pub.Encrypt(list, size+1);
    } catch(const std::exception &ex) {
        std::cout << "Error encrypt: " << ex.what() << "\n";
        return;
    }

    // Decrypt
    std::vector<unsigned char> dec;
    try {
        dec = priv.Decrypt(enc, size);
    } catch(const std::exception &ex) {
        std::cout << "Error decrypt: " << ex.what() << "\n";
        return;
    }

    if (dec.size() != list.size()) {
        std::cout << "Error: mismatch size between plain & dec\n";
        return;
    }
    for (size_t i = 0; i < list.size(); i++) {
        if (list[i] != dec[i]) {
            std::cout << "Error mismatch at index " << i << "\n";
            return;
        }
    }
    std::cout << "TestEncriptDecript => OK\n";
    std::cout << "========================================\n\n";
}

// -------------------------------------------------------
// MAIN
// -------------------------------------------------------
int main() {
    // 1) Sinh 1 cặp khóa 8192 bit => "k8192.pub" + "k8192.key"
    TestCreateRSAKey8192();

    // 2) Kiểm tra save/reload (cũng 8192 bit, nhưng lưu vào "test8192")
    TestKeySaveReload();

    // 3) Test find prime
    Test2();

    // 4) Test encrypt/decrypt 31 bytes => "k8192"
    TestEncriptDecript();

    // 5) Test encrypt/decrypt vô hạn => "k8192"
    //    (comment lại nếu không muốn vòng lặp vô hạn)
    // TestEncriptDecript2();

    return 0;
}
