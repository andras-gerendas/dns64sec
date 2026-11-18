/**
 * @file OpensslDeleter.h
 * @author Andras Attila Gerendas
 * @brief Utility functions for safe OpenSSL memory management
 * @version 0.1
 * @date 2026-11-18
 *
 * @copyright Copyright (c) 2026
 *
 */

#ifndef DNS64SEC_OPENSSL_DELETER
#define DNS64SEC_OPENSSL_DELETER

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>

#include <memory>

template <typename T, auto FreeFn>
struct OpenSSLDeleter {
    void operator()(T* ptr) const noexcept {
        if (ptr != nullptr) {
            FreeFn(ptr);
        }
    }
};

inline void openssl_free_bytes(uint8_t* ptr) noexcept {
    OPENSSL_free(ptr);
}

using BioPtr          = std::unique_ptr<BIO, OpenSSLDeleter<BIO, &BIO_free>>;
using BnPtr           = std::unique_ptr<BIGNUM, OpenSSLDeleter<BIGNUM, &BN_free>>;
using EcdsaSigPtr     = std::unique_ptr<ECDSA_SIG, OpenSSLDeleter<ECDSA_SIG, &ECDSA_SIG_free>>;
using EvpMdCtxPtr     = std::unique_ptr<EVP_MD_CTX, OpenSSLDeleter<EVP_MD_CTX, &EVP_MD_CTX_free>>;
using EvpPkeyPtr      = std::unique_ptr<EVP_PKEY, OpenSSLDeleter<EVP_PKEY, &EVP_PKEY_free>>;
using EvpPkeyCtxPtr   = std::unique_ptr<EVP_PKEY_CTX, OpenSSLDeleter<EVP_PKEY_CTX, &EVP_PKEY_CTX_free>>;
using OpenSSLBytesPtr = std::unique_ptr<uint8_t, OpenSSLDeleter<uint8_t, &openssl_free_bytes>>;

#endif // DNS64SEC_OPENSSL_DELETER