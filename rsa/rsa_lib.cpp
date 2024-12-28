#include "rsa_lib.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <random>
#include <chrono>
#include <thread>

/*
  --------------------------------------------------------------------------------
  BIẾN TOÀN CỤC TƯƠNG ỨNG zero, one, two
  --------------------------------------------------------------------------------
*/
static const mpz_class ZERO(0);
static const mpz_class ONE(1);
static const mpz_class TWO(2);

/*
  --------------------------------------------------------------------------------
  ĐỊNH NGHĨA CHI TIẾT CÁC HÀM BigInt
  --------------------------------------------------------------------------------
*/

// NewDecimal
mpz_class NewDecimal(const std::string &decimal) {
    mpz_class ret;
    ret.set_str(decimal, 10); // base=10
    return ret;
}

// PowModulo (b^e mod m)
mpz_class PowModulo(const mpz_class &b, const mpz_class &e, const mpz_class &m) {
    mpz_class base = b, exp = e, result = 1;
    mpz_class mod = m;
    while (exp > 0) {
        if (mpz_odd_p(exp.get_mpz_t())) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

// PowModulo2
mpz_class PowModulo2(const mpz_class &n, const mpz_class &exp, const mpz_class &mod) {
    if (mod == ZERO) {
        return n;
    }
    mpz_class pp = 1;
    mpz_class nb = n;
    mpz_class expb = exp;
    while (expb > 0) {
        if (mpz_odd_p(expb.get_mpz_t())) {
            pp = (pp * nb) % mod;
        }
        nb = (nb * nb) % mod;
        expb >>= 1;
    }
    return pp;
}

// GetRandom(size) => random 1 số bigInt exactly size bits
mpz_class GetRandom(int size) {
    if (size <= 0) {
        return ZERO;
    }

    static std::random_device rd;
    static gmp_randclass rstate(gmp_randinit_default);

    while (true) {
        auto nowSeed = std::chrono::high_resolution_clock::now()
                           .time_since_epoch().count();
        rstate.seed(rd() ^ (unsigned long)nowSeed);

        mpz_class candidate = rstate.get_z_bits(size);

        if (candidate != 0 && mpz_sizeinbase(candidate.get_mpz_t(), 2) == (unsigned)size) {
            return candidate;
        }
    }
}

/*
  Miller-Rabin check (IsPrime, isPrimeForRadix)
*/
static bool isPrimeForRadix(const mpz_class &n, const mpz_class &radix);

bool IsPrime(const mpz_class &n) {
    if (n == ZERO) return false;
    if (n == ONE)  return false;
    // n chẵn => false
    if ((n & 1) == 0) {
        return false;
    }
    // Danh sách base test
    static const long radixList[] = {
        3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,
        59,61,67,71,73,79,83,89,97
    };
    for (auto rr : radixList) {
        mpz_class base(rr);
        // nếu n chia hết cho rr => trừ khi n == rr
        if ((n % base) == 0 && n != base) {
            return false;
        }
        if (!isPrimeForRadix(n, base)) {
            return false;
        }
    }
    return true;
}

// isPrimeForRadix => Miller-Rabin
static bool isPrimeForRadix(const mpz_class &n, const mpz_class &radix) {
    if (n == radix) {
        return true;
    }

    mpz_class dd = n - 1;
    int hh = 0;
    while ((dd & 1) == 0) {
        dd >>= 1;
        hh++;
    }

    mpz_class nn1 = n - 1;
    mpz_class xx = PowModulo(radix, dd, n);
    if (xx == ONE || xx == nn1) {
        return true;
    }

    for (int i = 1; i < hh; i++) {
        xx = PowModulo(xx, TWO, n);
        if (xx == ONE) {
            return false;
        }
        if (xx == nn1) {
            return true;
        }
    }
    return false;
}

// GetNextPrime: tìm prime >= n, +2
mpz_class GetNextPrime(mpz_class n, bool verbose, bool debug) {
    if (debug) {
        verbose = false;
    }
    // n chẵn => +1 cho lẻ
    if ((n & 1) == 0) {
        n += 1;
    }

    bool prime = false;
    while (!prime) {
        n += 2;
        auto t0 = std::chrono::high_resolution_clock::now();
        prime = IsPrime(n);

        if (verbose) {
            std::cout << ".";
        }
        if (debug) {
            auto t1 = std::chrono::high_resolution_clock::now();
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
            std::cout << (prime ? "true" : "false") << " (" << ms << "ms): " << n.get_str() << "\n";
        }
    }
    if (verbose) {
        std::cout << std::endl;
    }
    return n;
}

// GetRandomPrime => random 1 số size bits => GetNextPrime
mpz_class GetRandomPrime(int size, bool verbose, bool debug) {
    mpz_class n = GetRandom(size);
    mpz_class p = GetNextPrime(n, verbose, debug);
    return p;
}

/*
  --------------------------------------------------------------------------------
  ĐỊNH NGHĨA CHI TIẾT CÁC HÀM RSA
  --------------------------------------------------------------------------------
*/

// CreateRSAKey(...)
void CreateRSAKey(int keyBitSize, bool verbose, bool debug,
                  PublicKey &pubKey, PrivateKey &privKey) 
{
    if (keyBitSize % 64 != 0) {
        throw std::runtime_error("number of bits should be a multiple of 64");
    }

    int pSize = keyBitSize / 2;
    if (verbose) {
        std::cout << "Compute RSA keys size: " << pSize*2 << " bits\n";
    }

    mpz_class p(0), q(0);
    bool foundP = false, foundQ = false;

    // Tạo 2 thread để tìm p, q
    std::thread t1([&](){
        while (!foundP) {
            p = GetRandomPrime(pSize, verbose, debug);
            if ((int)mpz_sizeinbase(p.get_mpz_t(), 2) == pSize) {
                foundP = true;
                if (verbose) {
                    std::cout << "prime (" << p.get_str() << ")\n";
                }
            } else {
                if (verbose) {
                    std::cout << "Bad one, recompute it\n";
                }
            }
        }
    });

    std::thread t2([&](){
        while (!foundQ) {
            q = GetRandomPrime(pSize, verbose, debug);
            if ((int)mpz_sizeinbase(q.get_mpz_t(), 2) == pSize) {
                foundQ = true;
                if (verbose) {
                    std::cout << "prime (" << q.get_str() << ")\n";
                }
            } else {
                if (verbose) {
                    std::cout << "Bad one, recompute it\n";
                }
            }
        }
    });

    // chờ p, q
    while (!foundP || !foundQ) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    t1.join();
    t2.join();

    mpz_class nn = p * q;
    if (verbose) {
        std::cout << "size=" << mpz_sizeinbase(nn.get_mpz_t(), 2)
                  << ": n=" << nn.get_str() << "\n";
    }

    // phi = (p-1)*(q-1)
    mpz_class phi = (p - 1) * (q - 1);
    if (verbose) {
        std::cout << "phi=" << phi.get_str() << "\n";
    }

    // Tìm e
    mpz_class ee = GetRandom(keyBitSize / 4);
    ee = GetNextPrime(ee, verbose, false);
    {
        mpz_class tmp;
        mpz_gcd(tmp.get_mpz_t(), phi.get_mpz_t(), ee.get_mpz_t());
        while (tmp != ONE) {
            ee += 2;
            ee = GetNextPrime(ee, verbose, false);
            mpz_gcd(tmp.get_mpz_t(), phi.get_mpz_t(), ee.get_mpz_t());
        }
    }
    if (verbose) {
        std::cout << "e=" << ee.get_str() << "\n";
    }

    // d = e^-1 mod phi
    mpz_class dd;
    if (!mpz_invert(dd.get_mpz_t(), ee.get_mpz_t(), phi.get_mpz_t())) {
        throw std::runtime_error("ModInverse(e, phi) failed");
    }
    if (verbose) {
        std::cout << "d=" << dd.get_str() << "\n";
    }

    pubKey.nn = nn;
    pubKey.ee = ee;
    privKey.nn = nn;
    privKey.dd = dd;
}

// EncryptFile(...)
int EncryptFile(const std::string &sourcePath,
                const std::string &targetPath,
                const std::string &keyPath)
{
    // đọc publicKey từ file
    PublicKey pub;
    {
        std::ifstream fin(keyPath);
        if (!fin) {
            std::cerr << "Cannot open publicKey file\n";
            return -1;
        }
        std::string data;
        std::getline(fin, data);
        auto pos = data.find('-');
        if (pos == std::string::npos) {
            std::cerr << "Public key file invalid\n";
            return -1;
        }
        pub.nn.set_str(data.substr(0, pos), 16);
        pub.ee.set_str(data.substr(pos+1), 16);
    }

    int bufferSize = pub.GetRSAKeySize()/8 - 1;

    // mở file input
    std::ifstream inFile(sourcePath, std::ios::binary);
    if (!inFile) {
        std::cerr << "Cannot open source file\n";
        return -1;
    }
    // tạo file output
    std::ofstream outFile(targetPath, std::ios::binary);
    if (!outFile) {
        std::cerr << "Cannot open target file\n";
        return -1;
    }

    std::vector<unsigned char> data(bufferSize);
    int lastN = 0;

    while (true) {
        inFile.read((char*)data.data(), bufferSize);
        std::streamsize n = inFile.gcount();
        if (n <= 0) {
            break;
        }
        data.resize(n);

        std::vector<unsigned char> enc;
        try {
            enc = pub.Encrypt(data, bufferSize+1);
        } catch (...) {
            std::cerr << "Encrypt error\n";
            return -1;
        }
        outFile.write((char*)enc.data(), enc.size());

        lastN = (int)n;
        data.resize(bufferSize);
    }

    // Ghi trailer 2 byte
    unsigned char trailer[2];
    trailer[0] = (unsigned char)(lastN % 256);
    trailer[1] = (unsigned char)(lastN / 256);
    outFile.write((char*)trailer, 2);

    return 0;
}

// DecryptFile(...)
int DecryptFile(const std::string &sourcePath,
                const std::string &targetPath,
                const std::string &keyPath)
{
    // đọc privateKey
    PrivateKey priv;
    {
        std::ifstream fin(keyPath);
        if (!fin) {
            std::cerr << "Cannot open privateKey file\n";
            return -1;
        }
        std::string data;
        std::getline(fin, data);
        auto pos = data.find('-');
        if (pos == std::string::npos) {
            std::cerr << "Private key file invalid\n";
            return -1;
        }
        priv.nn.set_str(data.substr(0, pos), 16);
        priv.dd.set_str(data.substr(pos+1), 16);
    }

    int bufferSize = priv.GetRSAKeySize()/8 - 1;

    std::ifstream inFile(sourcePath, std::ios::binary);
    if (!inFile) {
        std::cerr << "Cannot open source\n";
        return -1;
    }
    std::ofstream outFile(targetPath, std::ios::binary);
    if (!outFile) {
        std::cerr << "Cannot open target\n";
        return -1;
    }

    std::vector<unsigned char> prevData(bufferSize+1), dataBlock(bufferSize+1);
    std::vector<unsigned char> dec;
    int nnCount = 0;

    while (true) {
        inFile.read((char*)dataBlock.data(), bufferSize+1);
        std::streamsize n = inFile.gcount();
        if (n <= 0) {
            break;
        }
        dataBlock.resize(n);

        if (nnCount > 0) {
            // decrypt prevData
            dec = priv.Decrypt(prevData, bufferSize);
            // nếu block này chỉ có 2 byte => trailer => cắt
            if (n == 2) {
                int slen = (int)dataBlock[0] + (int)dataBlock[1]*256;
                if (slen <= bufferSize) {
                    dec.erase(dec.begin(), dec.begin() + (bufferSize - slen));
                }
            }
            outFile.write((char*)dec.data(), dec.size());
        }

        prevData = dataBlock;
        prevData.resize(bufferSize+1);

        nnCount++;
        dataBlock.resize(bufferSize+1);
    }

    return 0;
}

// GetKeys(path): đọc path.pub => publicKey, path.key => privateKey
int GetKeys(const std::string &path, PublicKey &pub, PrivateKey &priv) {
    // publicKey
    {
        std::ifstream fpub(path + ".pub");
        if (!fpub) {
            std::cerr << "Cannot open " << path << ".pub\n";
            return -1;
        }
        std::string data;
        std::getline(fpub, data);
        auto pos = data.find('-');
        if (pos == std::string::npos) {
            std::cerr << "Error reading public key\n";
            return -1;
        }
        pub.nn.set_str(data.substr(0, pos), 16);
        pub.ee.set_str(data.substr(pos+1), 16);
        if (pub.nn == 0 || pub.ee == 0) {
            std::cerr << "Error reading public key (zero)\n";
            return -1;
        }
    }

    // privateKey
    {
        std::ifstream fpriv(path + ".key");
        if (!fpriv) {
            std::cerr << "Cannot open " << path << ".key\n";
            return -1;
        }
        std::string data;
        std::getline(fpriv, data);
        auto pos = data.find('-');
        if (pos == std::string::npos) {
            std::cerr << "Error reading private key\n";
            return -1;
        }
        priv.nn.set_str(data.substr(0, pos), 16);
        priv.dd.set_str(data.substr(pos+1), 16);
        if (priv.nn == 0 || priv.dd == 0) {
            std::cerr << "Error reading private key (zero)\n";
            return -1;
        }
    }

    return 0;
}

// SaveKeys(path, pub, priv) => path.pub, path.key
int SaveKeys(const std::string &path, const PublicKey &pub, const PrivateKey &priv) {
    {
        std::ofstream fpub(path + ".pub");
        if (!fpub) {
            std::cerr << "Cannot create " << path << ".pub\n";
            return -1;
        }
        fpub << pub.ToHexa() << std::endl;
    }
    {
        std::ofstream fpriv(path + ".key");
        if (!fpriv) {
            std::cerr << "Cannot create " << path << ".key\n";
            return -1;
        }
        fpriv << priv.ToHexa() << std::endl;
    }
    return 0;
}

// GetPublicKey(path) => new PublicKey
PublicKey* GetPublicKey(const std::string &path) {
    std::ifstream fin(path);
    if (!fin) {
        throw std::runtime_error("Error reading public key file");
    }
    std::string data;
    std::getline(fin, data);
    auto pos = data.find('-');
    if (pos == std::string::npos) {
        throw std::runtime_error("Error reading public key (invalid format)");
    }
    std::string nHex = data.substr(0, pos);
    std::string eHex = data.substr(pos+1);

    PublicKey* key = new PublicKey();
    key->nn.set_str(nHex, 16);
    key->ee.set_str(eHex, 16);
    if (key->nn == 0 || key->ee == 0) {
        delete key;
        throw std::runtime_error("Error reading public key (zero)");
    }
    return key;
}

// GetPrivateKey(path) => new PrivateKey
PrivateKey* GetPrivateKey(const std::string &path) {
    std::ifstream fin(path);
    if (!fin) {
        throw std::runtime_error("Error reading private key file");
    }
    std::string data;
    std::getline(fin, data);
    auto pos = data.find('-');
    if (pos == std::string::npos) {
        throw std::runtime_error("Error reading private key (invalid format)");
    }
    std::string nHex = data.substr(0, pos);
    std::string dHex = data.substr(pos+1);

    PrivateKey* key = new PrivateKey();
    key->nn.set_str(nHex, 16);
    key->dd.set_str(dHex, 16);
    if (key->nn == 0 || key->dd == 0) {
        delete key;
        throw std::runtime_error("Error reading private key (zero)");
    }
    return key;
}

/*
  --------------------------------------------------------------------------------
  ĐỊNH NGHĨA PHƯƠNG THỨC CHO struct PublicKey
  --------------------------------------------------------------------------------
*/
std::string PublicKey::ToHexa() const {
    // format "%x-%x"
    std::ostringstream oss;
    oss << nn.get_str(16) << "-" << ee.get_str(16);
    return oss.str();
}

int PublicKey::GetRSAKeySize() const {
    return mpz_sizeinbase(nn.get_mpz_t(), 2);
}

std::vector<unsigned char> PublicKey::Encrypt(const std::vector<unsigned char> &data, int size) const {
    if ((int)data.size() > GetRSAKeySize()/8) {
        throw std::runtime_error("Data too large. It cannot exceed keySize/8 bytes");
    }
    // chuyển data -> mpz
    mpz_class tmp(0);
    {
        // build chuỗi hex
        std::string hex;
        hex.reserve(data.size()*2);
        for (auto c : data) {
            char buf[3];
            sprintf(buf, "%02x", c);
            hex.append(buf);
        }
        if (!hex.empty()) {
            tmp.set_str(hex, 16);
        }
    }
    // mã hoá: tmp^ee mod nn
    mpz_class encVal = PowModulo(tmp, ee, nn);

    // chuyển về bytes
    std::string encHex = encVal.get_str(16);
    if (encHex.size() & 1) {
        encHex.insert(encHex.begin(), '0');
    }
    std::vector<unsigned char> dec;
    dec.reserve(encHex.size()/2);
    for (size_t i = 0; i < encHex.size(); i += 2) {
        unsigned int val;
        sscanf(encHex.substr(i,2).c_str(), "%x", &val);
        dec.push_back((unsigned char)val);
    }

    // padding
    if ((int)dec.size() < size) {
        int dif = size - (int)dec.size();
        std::vector<unsigned char> dataRet(size, 0);
        for (size_t i = 0; i < dec.size(); i++) {
            dataRet[i + dif] = dec[i];
        }
        return dataRet;
    }
    return dec;
}

/*
  --------------------------------------------------------------------------------
  ĐỊNH NGHĨA PHƯƠNG THỨC CHO struct PrivateKey
  --------------------------------------------------------------------------------
*/
std::string PrivateKey::ToHexa() const {
    std::ostringstream oss;
    oss << nn.get_str(16) << "-" << dd.get_str(16);
    return oss.str();
}

int PrivateKey::GetRSAKeySize() const {
    return mpz_sizeinbase(nn.get_mpz_t(), 2);
}

std::vector<unsigned char> PrivateKey::Decrypt(const std::vector<unsigned char> &data, int size) const {
    if ((int)data.size() > GetRSAKeySize()/8) {
        throw std::runtime_error("Data too large. It cannot exceed keySize/8 bytes");
    }
    mpz_class tmp(0);
    {
        std::string hex;
        hex.reserve(data.size()*2);
        for (auto c : data) {
            char buf[3];
            sprintf(buf, "%02x", c);
            hex.append(buf);
        }
        if (!hex.empty()) {
            tmp.set_str(hex, 16);
        }
    }
    mpz_class decVal = PowModulo(tmp, dd, nn);

    std::string decHex = decVal.get_str(16);
    if (decHex.size() & 1) {
        decHex.insert(decHex.begin(), '0');
    }
    std::vector<unsigned char> dec;
    dec.reserve(decHex.size()/2);
    for (size_t i = 0; i < decHex.size(); i += 2) {
        unsigned int val;
        sscanf(decHex.substr(i,2).c_str(), "%x", &val);
        dec.push_back((unsigned char)val);
    }

    if ((int)dec.size() < size) {
        int dif = size - (int)dec.size();
        std::vector<unsigned char> dataRet(size, 0);
        for (size_t i = 0; i < dec.size(); i++) {
            dataRet[i + dif] = dec[i];
        }
        return dataRet;
    }
    return dec;
}
