// rsa_lib.h
#ifndef RSA_LIB_H
#define RSA_LIB_H

#include <gmpxx.h>
#include <vector>
#include <string>
#include <exception>

// Define PublicKey and PrivateKey structures
struct PublicKey {
    mpz_class nn;
    mpz_class ee;

    std::vector<unsigned char> Encrypt(const std::vector<unsigned char> &data) const;
    std::string ToHexa() const;
    int GetRSAKeySize() const;
};

struct PrivateKey {
    mpz_class nn;
    mpz_class dd;

    std::vector<unsigned char> Decrypt(const std::vector<unsigned char> &data) const;
    std::string ToHexa() const;
    int GetRSAKeySize() const;
};

// RSA utility functions
bool IsPrime(const mpz_class &n);
mpz_class GetNextPrime(mpz_class n);
mpz_class GetRandom(int size);
mpz_class GetRandomPrime(int size, bool verbose, bool debug);
void CreateRSAKey(int keyBitSize, bool verbose, bool debug, PublicKey &pubKey, PrivateKey &privKey);

#endif // RSA_LIB_H
