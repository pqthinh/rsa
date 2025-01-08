// rsa_lib.cpp
#include "rsa_lib.h"
#include <gmp.h>
#include <gmpxx.h>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <random>
#include <chrono>
#include <thread>

/*
  --------------------------------------------------------------------------------
  DEFINITIONS OF BIGINT FUNCTIONS
  --------------------------------------------------------------------------------
*/

// Check if a number is prime using GMP
bool IsPrime(const mpz_class &n)
{
    // mpz_probab_prime_p returns:
    // 0 - composite
    // 1 - probably prime
    // 2 - definitely prime
    return mpz_probab_prime_p(n.get_mpz_t(), 25) > 0;
}

// Get the next prime number using GMP
mpz_class GetNextPrime(mpz_class n)
{
    mpz_nextprime(n.get_mpz_t(), n.get_mpz_t());
    return n;
}

// Generate a random number of specified bit size
mpz_class GetRandom(int size)
{
    gmp_randclass rstate(gmp_randinit_default);
    // Seed based on system time
    unsigned long seed = std::chrono::system_clock::now().time_since_epoch().count();
    rstate.seed(seed);
    mpz_class rand_num = rstate.get_z_bits(size);
    // Ensure the number has the correct bit size and is odd
    rand_num |= (mpz_class(1) << (size - 1)) | 1;
    return rand_num;
}

// Generate a random prime number of specified bit size
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
  DEFINITIONS OF RSA FUNCTIONS
  --------------------------------------------------------------------------------
*/

// Create RSA keys
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

    // Create two threads to generate p and q concurrently
    std::thread t1([&]()
                   {
        generate_prime(p, "p"); });
    std::thread t2([&]()
                   {
        generate_prime(q, "q"); });

    t1.join();
    t2.join();

    // Ensure p and q are different
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

    // Choose e
    mpz_class ee = 65537; // Commonly used prime
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

    // Find d
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

// Encrypt data using the public key
std::vector<unsigned char> PublicKey::Encrypt(const std::vector<unsigned char> &data) const
{
    mpz_class m;
    // Convert data to integer
    mpz_import(m.get_mpz_t(), data.size(), 1, 1, 0, 0, data.data());

    // Encrypt: c = m^e mod n
    mpz_class c;
    mpz_powm(c.get_mpz_t(), m.get_mpz_t(), ee.get_mpz_t(), nn.get_mpz_t());

    // Export encrypted number to bytes
    size_t count;
    unsigned char *c_bytes = static_cast<unsigned char *>(mpz_export(NULL, &count, 1, 1, 0, 0, c.get_mpz_t()));
    if (c_bytes == nullptr) {
        throw std::runtime_error("mpz_export failed during encryption");
    }
    std::vector<unsigned char> encrypted(c_bytes, c_bytes + count);
    free(c_bytes);

    // Padding if necessary
    size_t keyBytes = GetRSAKeySize() / 8;
    if (encrypted.size() < keyBytes)
    {
        encrypted.insert(encrypted.begin(), keyBytes - encrypted.size(), 0);
    }

    return encrypted;
}

// Decrypt data using the private key
std::vector<unsigned char> PrivateKey::Decrypt(const std::vector<unsigned char> &data) const
{
    mpz_class c;
    // Convert data to integer
    mpz_import(c.get_mpz_t(), data.size(), 1, 1, 0, 0, data.data());

    // Decrypt: m = c^d mod n
    mpz_class m;
    mpz_powm(m.get_mpz_t(), c.get_mpz_t(), dd.get_mpz_t(), nn.get_mpz_t());

    // Export decrypted number to bytes
    size_t count;
    unsigned char *m_bytes = static_cast<unsigned char *>(mpz_export(NULL, &count, 1, 1, 0, 0, m.get_mpz_t()));
    if (m_bytes == nullptr && count == 0) {
        throw std::runtime_error("mpz_export failed during decryption");
    }
    std::vector<unsigned char> decrypted(m_bytes, m_bytes + count);
    free(m_bytes);

    return decrypted;
}

// Convert PublicKey to hexadecimal string
std::string PublicKey::ToHexa() const
{
    std::ostringstream oss;
    oss << nn.get_str(16) << "-" << ee.get_str(16);
    return oss.str();
}

// Get RSA key size in bits
int PublicKey::GetRSAKeySize() const
{
    return mpz_sizeinbase(nn.get_mpz_t(), 2);
}

// Convert PrivateKey to hexadecimal string
std::string PrivateKey::ToHexa() const
{
    std::ostringstream oss;
    oss << nn.get_str(16) << "-" << dd.get_str(16);
    return oss.str();
}

// Get RSA key size in bits
int PrivateKey::GetRSAKeySize() const
{
    return mpz_sizeinbase(nn.get_mpz_t(), 2);
}
