#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include "rsa_lib.h"

// -----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------
void TestKeySaveReload() {
    std::cout << "=== TestKeySaveReload ===\n";
    PublicKey pub;
    PrivateKey priv;

    try {
        // tạo cặp khóa 256-bit
        CreateRSAKey(256, false, false, pub, priv);
    } catch (const std::exception &ex) {
        std::cout << "Error creating keys: " << ex.what() << std::endl;
        return;
    }

    // Lưu
    if (SaveKeys("k256", pub, priv) != 0) {
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
    if (GetKeys("k256", pub2, priv2) != 0) {
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

// -----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------
void Test2() {
    std::cout << "=== Test2 (GetNextPrime) ===\n";
    // n = NewDecimal(...) 
    std::string dec_str = 
    "1345254657457568223445235435634674567567345345356434556756786798805486589567877532456"
    "345756789789087900979432614523444674687898087908907066465234634567458456967894567345624"
    "657856975768945763455234655467856876896584652345243635674687649673653245646654568756645"
    "67458656787535635687456734654982763834563651763937";

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

// -----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------
void TestEncriptDecript2() {
    std::cout << "=== TestEncriptDecript2 ===\n";
    PublicKey pub;
    PrivateKey priv;
    if (GetKeys("k256", pub, priv) != 0) {
        std::cout << "Error reading key: k256\n";
        return;
    }

    int size = pub.GetRSAKeySize()/8 - 1;
    std::cout << "Load keys done. start test: size: " << size << "\n";

    std::vector<unsigned char> list(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned short> dist(0, 255);

    long long nn = 0;
    while (true) {
        for (int i = 0; i < size; i++) {
            list[i] = (unsigned char)dist(gen);
        }
        std::vector<unsigned char> c, d;
        try {
            c = pub.Encrypt(list, size+1);
            d = priv.Decrypt(c, size);
        } catch (const std::exception &ex) {
            std::cout << "Error: " << ex.what() << "\n";
            return;
        }

        if (d.size() != list.size()) {
            std::cout << "Error size mismatch\n";
            return;
        }
        for (size_t i = 0; i < list.size(); i++) {
            if (list[i] != d[i]) {
                std::cout << "Error mismatch at index " << i << "\n";
                return;
            }
        }
        nn++;
        if (nn % 1000 == 0) {
            std::cout << nn << "\n";
        }
    }
    // Lưu ý: vòng lặp vô tận
}

// -----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------
void TestEncriptDecript() {
    std::cout << "=== TestEncriptDecript ===\n";
    PublicKey pub;
    PrivateKey priv;
    if (GetKeys("k256", pub, priv) != 0) {
        std::cout << "Error reading key: k256\n";
        return;
    }

    int size = pub.GetRSAKeySize()/8 - 1;
    std::cout << "Load keys done. size: " << size << "\n";

    std::vector<unsigned char> list {
        15, 211, 218, 155, 207, 209, 212, 102, 241, 192,
        130, 92, 10, 92, 213, 236, 172, 190, 189, 213,
        116, 66, 8, 33, 132, 16, 66, 8, 33, 132, 16
    };
    std::cout << "list " << list.size() << " bytes\n";

    std::vector<unsigned char> c, d;
    try {
        c = pub.Encrypt(list, size+1);
        d = priv.Decrypt(c, size);
    } catch(const std::exception &ex) {
        std::cout << "Error: " << ex.what() << "\n";
        return;
    }

    if (d.size() != list.size()) {
        std::cout << "Error size mismatch\n";
        return;
    }
    for (size_t i = 0; i < list.size(); i++) {
        if (list[i] != d[i]) {
            std::cout << "Error mismatch at index " << i << "\n";
            return;
        }
    }
    std::cout << "TestEncriptDecript => OK\n";
    std::cout << "========================================\n\n";
}

// -----------------------------------------------------------------------------------
// MAIN
// -----------------------------------------------------------------------------------
int main() {
    // Gọi các test
    TestKeySaveReload();      // Tạo/lưu/đọc key 256 bit => so sánh
    Test2();                  // Test getNextPrime
    TestEncriptDecript();     // Test encrypt-decrypt 1 mảng byte
    // TestEncriptDecript2(); // (Nếu bạn muốn chạy thử, vòng lặp vô hạn)

    return 0;
}
