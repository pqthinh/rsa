#ifndef RSA_LIB_H
#define RSA_LIB_H

#include <gmpxx.h>
#include <vector>
#include <string>

/*
  --------------------------------------------------------------------------------
  KHAI BÁO struct, hàm tương tự như BigInt.go + rsa.go
  --------------------------------------------------------------------------------
*/

// ----------------- struct PublicKey -----------------
struct PublicKey {
    mpz_class nn;  // tương đương publicKey.nn
    mpz_class ee;  // tương đương publicKey.ee

    // Các hàm member tương tự (k *PublicKey) trong Go
    std::string ToHexa() const;
    int GetRSAKeySize() const;
    std::vector<unsigned char> Encrypt(const std::vector<unsigned char> &data, int size) const;
};

// ----------------- struct PrivateKey -----------------
struct PrivateKey {
    mpz_class nn;  // tương đương privateKey.nn
    mpz_class dd;  // tương đương privateKey.dd

    std::string ToHexa() const;
    int GetRSAKeySize() const;
    std::vector<unsigned char> Decrypt(const std::vector<unsigned char> &data, int size) const;
};

mpz_class NewDecimal(const std::string &decimal);
mpz_class PowModulo(const mpz_class &b, const mpz_class &e, const mpz_class &m);
mpz_class PowModulo2(const mpz_class &n, const mpz_class &exp, const mpz_class &mod);
mpz_class GetRandom(int size);
bool IsPrime(const mpz_class &n);
mpz_class GetNextPrime(mpz_class n, bool verbose=false, bool debug=false);
mpz_class GetRandomPrime(int size, bool verbose=false, bool debug=false);

void CreateRSAKey(int keyBitSize, bool verbose, bool debug,
                  PublicKey &pubKey, PrivateKey &privKey);
int EncryptFile(const std::string &sourcePath,
                const std::string &targetPath,
                const std::string &keyPath);
int DecryptFile(const std::string &sourcePath,
                const std::string &targetPath,
                const std::string &keyPath);

int GetKeys(const std::string &path, PublicKey &pub, PrivateKey &priv);
int SaveKeys(const std::string &path, const PublicKey &pub, const PrivateKey &priv);
PublicKey*  GetPublicKey(const std::string &path);
PrivateKey* GetPrivateKey(const std::string &path);

#endif