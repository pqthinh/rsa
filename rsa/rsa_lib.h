#ifndef RSA_LIB_H
#define RSA_LIB_H

#include <gmpxx.h>
#include <string>
#include <vector>

// Cấu trúc khóa công khai
struct PublicKey {
    mpz_class nn; // modulus
    mpz_class ee; // public exponent

    std::string ToHexa() const;
    int GetRSAKeySize() const;
    std::vector<unsigned char> Encrypt(const std::vector<unsigned char> &data) const;
};

// Cấu trúc khóa riêng
struct PrivateKey {
    mpz_class nn; // modulus
    mpz_class dd; // private exponent

    std::string ToHexa() const;
    int GetRSAKeySize() const;
    std::vector<unsigned char> Decrypt(const std::vector<unsigned char> &data) const;
};

// Function declarations
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

PublicKey* GetPublicKey(const std::string &path);

PrivateKey* GetPrivateKey(const std::string &path);

#endif // RSA_LIB_H
