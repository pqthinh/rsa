#include "rsa_lib.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <random>
#include <chrono>
#include <thread>

/*
  --------------------------------------------------------------------------------
  ĐỊNH NGHĨA CHI TIẾT CÁC HÀM BigInt
  --------------------------------------------------------------------------------
*/

// Sử dụng hàm kiểm tra nguyên tố của GMP
bool IsPrime(const mpz_class &n)
{
    // mpz_probab_prime_p trả về:
    // 0 - composite
    // 1 - probably prime
    // 2 - definitely prime
    return mpz_probab_prime_p(n.get_mpz_t(), 25) > 0;
}

// Sử dụng hàm tìm số nguyên tố tiếp theo của GMP
mpz_class GetNextPrime(mpz_class n)
{
    mpz_nextprime(n.get_mpz_t(), n.get_mpz_t());
    return n;
}

// Sinh số ngẫu nhiên có kích thước bit mong muốn
mpz_class GetRandom(int size)
{
    gmp_randclass rstate(gmp_randinit_default);
    // Sử dụng seed dựa trên thời gian hệ thống
    unsigned long seed = std::chrono::system_clock::now().time_since_epoch().count();
    rstate.seed(seed);
    mpz_class rand_num = rstate.get_z_bits(size);
    // Đảm bảo số có đúng kích thước bit và là số lẻ
    rand_num |= (mpz_class(1) << (size - 1)) | 1;
    return rand_num;
}

// Sinh số nguyên tố ngẫu nhiên có kích thước bit mong muốn
mpz_class GetRandomPrime(int size, bool verbose, bool debug)
{
    mpz_class prime;
    while (true)
    {
        prime = GetRandom(size);
        prime = GetNextPrime(prime);
        if (IsPrime(prime))
        {
            if (verbose)
            {
                std::cout << "Prime found: " << prime.get_str() << "\n";
            }
            break;
        }
        if (verbose)
        {
            std::cout << "Prime candidate rejected, retrying...\n";
        }
    }
    return prime;
}

/*
  --------------------------------------------------------------------------------
  ĐỊNH NGHĨA CHI TIẾT CÁC HÀM RSA
  --------------------------------------------------------------------------------
*/

// Tạo khóa RSA
void CreateRSAKey(int keyBitSize, bool verbose, bool debug,
                  PublicKey &pubKey, PrivateKey &privKey)
{
    if (keyBitSize % 64 != 0)
    {
        throw std::runtime_error("Number of bits should be a multiple of 64");
    }

    int pSize = keyBitSize / 2;
    if (verbose)
    {
        std::cout << "Compute RSA keys size: " << keyBitSize << " bits\n";
    }

    mpz_class p, q;

    auto generate_prime = [&](mpz_class &prime, const std::string &name)
    {
        while (true)
        {
            prime = GetRandomPrime(pSize, verbose, debug);
            if (mpz_sizeinbase(prime.get_mpz_t(), 2) == static_cast<size_t>(pSize))
            {
                if (verbose)
                {
                    std::cout << name << " prime: " << prime.get_str() << "\n";
                }
                break;
            }
            if (verbose)
            {
                std::cout << "Generated prime does not have correct bit size. Retrying...\n";
            }
        }
    };

    // Tạo hai luồng để sinh p và q đồng thời
    bool foundP = false, foundQ = false;
    std::thread t1([&]()
                   {
        generate_prime(p, "p");
        foundP = true; });

    std::thread t2([&]()
                   {
        generate_prime(q, "q");
        foundQ = true; });

    t1.join();
    t2.join();

    // Kiểm tra p và q khác nhau
    while (p == q)
    {
        if (verbose)
        {
            std::cout << "p and q are equal, regenerating q...\n";
        }
        generate_prime(q, "q");
    }

    mpz_class nn = p * q;
    if (verbose)
    {
        std::cout << "n = p * q = " << nn.get_str() << " (" << mpz_sizeinbase(nn.get_mpz_t(), 2) << " bits)\n";
    }

    mpz_class phi = (p - 1) * (q - 1);
    if (verbose)
    {
        std::cout << "phi = " << phi.get_str() << "\n";
    }

    // Chọn e
    mpz_class ee = 65537; // Số e phổ biến
    mpz_class gcd;
    mpz_gcd(gcd.get_mpz_t(), phi.get_mpz_t(), ee.get_mpz_t());
    while (gcd != 1)
    {
        ee = GetNextPrime(ee + 2);
        mpz_gcd(gcd.get_mpz_t(), phi.get_mpz_t(), ee.get_mpz_t());
    }
    if (verbose)
    {
        std::cout << "e = " << ee.get_str() << "\n";
    }

    // Tìm d
    mpz_class dd;
    if (!mpz_invert(dd.get_mpz_t(), ee.get_mpz_t(), phi.get_mpz_t()))
    {
        throw std::runtime_error("Modular inverse failed");
    }
    if (verbose)
    {
        std::cout << "d = " << dd.get_str() << "\n";
    }

    pubKey.nn = nn;
    pubKey.ee = ee;
    privKey.nn = nn;
    privKey.dd = dd;
}

// Hàm mã hóa dữ liệu
std::vector<unsigned char> PublicKey::Encrypt(const std::vector<unsigned char> &data) const
{
    mpz_class m;
    // Chuyển đổi dữ liệu thành số nguyên
    mpz_import(m.get_mpz_t(), data.size(), 1, 1, 0, 0, data.data());

    // Mã hóa: c = m^e mod n
    mpz_class c;
    mpz_powm(c.get_mpz_t(), m.get_mpz_t(), ee.get_mpz_t(), nn.get_mpz_t());

    // Xuất kết quả thành byte array
    size_t count;
    unsigned char *c_bytes = static_cast<unsigned char *>(mpz_export(NULL, &count, 1, 1, 0, 0, c.get_mpz_t()));
    std::vector<unsigned char> encrypted(c_bytes, c_bytes + count);
    free(c_bytes);

    // Padding nếu cần thiết
    size_t keyBytes = GetRSAKeySize() / 8;
    if (encrypted.size() < keyBytes)
    {
        encrypted.insert(encrypted.begin(), keyBytes - encrypted.size(), 0);
    }

    return encrypted;
}

// Hàm giải mã dữ liệu
std::vector<unsigned char> PrivateKey::Decrypt(const std::vector<unsigned char> &data) const
{
    mpz_class c;
    // Chuyển đổi dữ liệu thành số nguyên
    mpz_import(c.get_mpz_t(), data.size(), 1, 1, 0, 0, data.data());

    // Giải mã: m = c^d mod n
    mpz_class m;
    mpz_powm(m.get_mpz_t(), c.get_mpz_t(), dd.get_mpz_t(), nn.get_mpz_t());

    // Xuất kết quả thành byte array
    size_t count;
    unsigned char *m_bytes = static_cast<unsigned char *>(mpz_export(NULL, &count, 1, 1, 0, 0, m.get_mpz_t()));
    std::vector<unsigned char> decrypted(m_bytes, m_bytes + count);
    free(m_bytes);

    return decrypted;
}

// Chuyển PublicKey thành chuỗi hexa
std::string PublicKey::ToHexa() const
{
    // định dạng "%x-%x"
    std::ostringstream oss;
    oss << nn.get_str(16) << "-" << ee.get_str(16);
    return oss.str();
}

// Lấy kích thước key RSA
int PublicKey::GetRSAKeySize() const
{
    return mpz_sizeinbase(nn.get_mpz_t(), 2);
}

// Chuyển PrivateKey thành chuỗi hexa
std::string PrivateKey::ToHexa() const
{
    std::ostringstream oss;
    oss << nn.get_str(16) << "-" << dd.get_str(16);
    return oss.str();
}

// Lấy kích thước key RSA
int PrivateKey::GetRSAKeySize() const
{
    return mpz_sizeinbase(nn.get_mpz_t(), 2);
}

// Hàm EncryptFile
int EncryptFile(const std::string &sourcePath,
                const std::string &targetPath,
                const std::string &keyPath)
{
    // Đọc publicKey từ file
    PublicKey pub;
    {
        std::ifstream fin(keyPath);
        if (!fin)
        {
            std::cerr << "Cannot open publicKey file\n";
            return -1;
        }
        std::string data;
        std::getline(fin, data);
        auto pos = data.find('-');
        if (pos == std::string::npos)
        {
            std::cerr << "Public key file invalid\n";
            return -1;
        }
        pub.nn.set_str(data.substr(0, pos), 16);
        pub.ee.set_str(data.substr(pos + 1), 16);
    }

    int bufferSize = pub.GetRSAKeySize() / 8 - 1;

    // Mở file input
    std::ifstream inFile(sourcePath, std::ios::binary);
    if (!inFile)
    {
        std::cerr << "Cannot open source file\n";
        return -1;
    }
    // Tạo file output
    std::ofstream outFile(targetPath, std::ios::binary);
    if (!outFile)
    {
        std::cerr << "Cannot open target file\n";
        return -1;
    }

    std::vector<unsigned char> data(bufferSize);
    int lastN = 0;

    while (true)
    {
        inFile.read(reinterpret_cast<char *>(data.data()), bufferSize);
        std::streamsize n = inFile.gcount();
        if (n <= 0)
        {
            break;
        }
        data.resize(n);

        std::vector<unsigned char> enc;
        try
        {
            enc = pub.Encrypt(data);
        }
        catch (...)
        {
            std::cerr << "Encrypt error\n";
            return -1;
        }
        outFile.write(reinterpret_cast<char *>(enc.data()), enc.size());

        lastN = static_cast<int>(n);
        data.resize(bufferSize);
    }

    // Ghi trailer 2 byte
    unsigned char trailer[2];
    trailer[0] = static_cast<unsigned char>(lastN % 256);
    trailer[1] = static_cast<unsigned char>(lastN / 256);
    outFile.write(reinterpret_cast<char *>(trailer), 2);

    return 0;
}

// Hàm DecryptFile
int DecryptFile(const std::string &sourcePath,
                const std::string &targetPath,
                const std::string &keyPath)
{
    // Đọc privateKey
    PrivateKey priv;
    {
        std::ifstream fin(keyPath);
        if (!fin)
        {
            std::cerr << "Cannot open privateKey file\n";
            return -1;
        }
        std::string data;
        std::getline(fin, data);
        auto pos = data.find('-');
        if (pos == std::string::npos)
        {
            std::cerr << "Private key file invalid\n";
            return -1;
        }
        priv.nn.set_str(data.substr(0, pos), 16);
        priv.dd.set_str(data.substr(pos + 1), 16);
    }

    int bufferSize = priv.GetRSAKeySize() / 8 - 1;

    std::ifstream inFile(sourcePath, std::ios::binary);
    if (!inFile)
    {
        std::cerr << "Cannot open source\n";
        return -1;
    }
    std::ofstream outFile(targetPath, std::ios::binary);
    if (!outFile)
    {
        std::cerr << "Cannot open target\n";
        return -1;
    }

    std::vector<unsigned char> prevData(priv.GetRSAKeySize() / 8, 0), dataBlock(priv.GetRSAKeySize() / 8, 0);
    std::vector<unsigned char> dec;
    int nnCount = 0;

    while (true)
    {
        inFile.read(reinterpret_cast<char *>(dataBlock.data()), priv.GetRSAKeySize() / 8);
        std::streamsize n = inFile.gcount();
        if (n <= 0)
        {
            break;
        }
        dataBlock.resize(n);

        if (nnCount > 0)
        {
            // Giải mã prevData
            dec = priv.Decrypt(prevData);

            // Nếu block này chỉ có 2 byte => trailer => cắt
            if (n == 2)
            {
                int slen = static_cast<int>(dataBlock[0]) + static_cast<int>(dataBlock[1]) * 256;
                if (slen <= bufferSize)
                {
                    if (slen < dec.size())
                    {
                        dec.erase(dec.begin() + slen, dec.end());
                    }
                }
            }
            outFile.write(reinterpret_cast<char *>(dec.data()), dec.size());
        }

        prevData = dataBlock;
        prevData.resize(priv.GetRSAKeySize() / 8);

        nnCount++;
        dataBlock.resize(priv.GetRSAKeySize() / 8);
    }

    return 0;
}

// Hàm GetKeys
int GetKeys(const std::string &path, PublicKey &pub, PrivateKey &priv)
{
    // PublicKey
    {
        std::ifstream fpub(path + ".pub");
        if (!fpub)
        {
            std::cerr << "Cannot open " << path << ".pub\n";
            return -1;
        }
        std::string data;
        std::getline(fpub, data);
        auto pos = data.find('-');
        if (pos == std::string::npos)
        {
            std::cerr << "Error reading public key\n";
            return -1;
        }
        pub.nn.set_str(data.substr(0, pos), 16);
        pub.ee.set_str(data.substr(pos + 1), 16);
        if (pub.nn == 0 || pub.ee == 0)
        {
            std::cerr << "Error reading public key (zero)\n";
            return -1;
        }
    }

    // PrivateKey
    {
        std::ifstream fpriv(path + ".key");
        if (!fpriv)
        {
            std::cerr << "Cannot open " << path << ".key\n";
            return -1;
        }
        std::string data;
        std::getline(fpriv, data);
        auto pos = data.find('-');
        if (pos == std::string::npos)
        {
            std::cerr << "Error reading private key\n";
            return -1;
        }
        priv.nn.set_str(data.substr(0, pos), 16);
        priv.dd.set_str(data.substr(pos + 1), 16);
        if (priv.nn == 0 || priv.dd == 0)
        {
            std::cerr << "Error reading private key (zero)\n";
            return -1;
        }
    }

    return 0;
}

// Hàm SaveKeys
int SaveKeys(const std::string &path, const PublicKey &pub, const PrivateKey &priv)
{
    {
        std::ofstream fpub(path + ".pub");
        if (!fpub)
        {
            std::cerr << "Cannot create " << path << ".pub\n";
            return -1;
        }
        fpub << pub.ToHexa() << std::endl;
    }
    {
        std::ofstream fpriv(path + ".key");
        if (!fpriv)
        {
            std::cerr << "Cannot create " << path << ".key\n";
            return -1;
        }
        fpriv << priv.ToHexa() << std::endl;
    }
    return 0;
}

// Hàm GetPublicKey
PublicKey *GetPublicKey(const std::string &path)
{
    std::ifstream fin(path);
    if (!fin)
    {
        throw std::runtime_error("Error reading public key file");
    }
    std::string data;
    std::getline(fin, data);
    auto pos = data.find('-');
    if (pos == std::string::npos)
    {
        throw std::runtime_error("Error reading public key (invalid format)");
    }
    std::string nHex = data.substr(0, pos);
    std::string eHex = data.substr(pos + 1);

    PublicKey *key = new PublicKey();
    key->nn.set_str(nHex, 16);
    key->ee.set_str(eHex, 16);
    if (key->nn == 0 || key->ee == 0)
    {
        delete key;
        throw std::runtime_error("Error reading public key (zero)");
    }
    return key;
}

// Hàm GetPrivateKey
PrivateKey *GetPrivateKey(const std::string &path)
{
    std::ifstream fin(path);
    if (!fin)
    {
        throw std::runtime_error("Error reading private key file");
    }
    std::string data;
    std::getline(fin, data);
    auto pos = data.find('-');
    if (pos == std::string::npos)
    {
        throw std::runtime_error("Error reading private key (invalid format)");
    }
    std::string nHex = data.substr(0, pos);
    std::string dHex = data.substr(pos + 1);

    PrivateKey *key = new PrivateKey();
    key->nn.set_str(nHex, 16);
    key->dd.set_str(dHex, 16);
    if (key->nn == 0 || key->dd == 0)
    {
        delete key;
        throw std::runtime_error("Error reading private key (zero)");
    }
    return key;
}
