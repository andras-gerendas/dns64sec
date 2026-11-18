/**
 * @file DnskeyBuilder.h
 * @author Andras Attila Gerendas
 * @brief Builder for a DNSKEY Resource Record
 * @version 0.1
 * @date 2026-10-23
 *
 * @copyright Copyright (c) 2026
 *
 */

#ifndef DNS64SEC_DNSKEY_BUILDER_H
#define DNS64SEC_DNSKEY_BUILDER_H

#include "OpensslDeleter.h"
#include "RRBuilder.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

class DnskeyBuilder : public RRBuilder {
    uint16_t flags{0};
    uint8_t protocol{0};
    uint8_t algorithm{0};
    std::string privateKey;
    std::string publicKey;

    public:
        DnskeyBuilder(const std::string &name, DnsMessage::ClassType qclass = DnsMessage::ClassType::IN) : RRBuilder(name, DnsMessage::RecordType::DNSKEY, qclass) {}

        virtual void buildBody(DnsMessage &target, uint16_t /*lengthLocation*/) override {
            target.addShort(flags);
            target.addByte(protocol);
            target.addByte(algorithm);

            if (publicKey.size() > 0) {
                addPublicKey(target);
            }

            target.setAnswerCount(target.getAnswerCount() + 1);
        }

        void addPublicKey(DnsMessage &target) {
            BioPtr bio(BIO_new_mem_buf(publicKey.data(), static_cast<int>(publicKey.size())));

            if (!bio) {
                return;
            }

            EvpPkeyPtr pkey(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr));

            if (!pkey) {
                return;
            }

            BIGNUM *n_raw = nullptr;
            BnPtr n_param;

            if (!EVP_PKEY_get_bn_param(pkey.get(), OSSL_PKEY_PARAM_RSA_N, &n_raw)) {
                return;
            }

            n_param.reset(n_raw);

            BIGNUM *e_raw = nullptr;
            BnPtr e_param;
            
            if (!EVP_PKEY_get_bn_param(pkey.get(), OSSL_PKEY_PARAM_RSA_E, &e_raw)) {
                return;
            }

            e_param.reset(e_raw);

            int e_bytes = BN_num_bytes(e_param.get());
            int n_bytes = BN_num_bytes(n_param.get());

            auto keyLength = 1 + e_bytes + n_bytes;

            auto publicKeyRaw = std::make_unique<uint8_t[]>(keyLength);

            publicKeyRaw[0] = (uint8_t)e_bytes;
            BN_bn2bin(e_param.get(), &publicKeyRaw[1]);
            BN_bn2bin(n_param.get(), &publicKeyRaw[1 + e_bytes]);

            target.addBytes(publicKeyRaw.get(), keyLength);
        }

        DnskeyBuilder& generateRsaKeyPair() {
            EvpPkeyPtr pkey(EVP_RSA_gen(3072));

            BioPtr bio(BIO_new(BIO_s_mem()));

            if (!bio) {
                return *this;
            }

            if (!PEM_write_bio_PrivateKey(bio.get(), pkey.get(), NULL, NULL, 0, NULL, NULL)) {
                return *this;
            }

            BUF_MEM *bioptr;
            BIO_get_mem_ptr(bio.get(), &bioptr);

            privateKey.resize(bioptr->length);
            memcpy(&privateKey[0], bioptr->data, bioptr->length);

            BIO_reset(bio.get());

            if (!PEM_write_bio_PUBKEY(bio.get(), pkey.get())) {
                return *this;
            }

            BIO_get_mem_ptr(bio.get(), &bioptr);

            publicKey.resize(bioptr->length);
            memcpy(&publicKey[0], bioptr->data, bioptr->length);

            return *this;
        }

        const std::string& getPrivateKey() {
            return privateKey;
        }

        DnskeyBuilder& setAlgorithm(uint8_t algorithm) {
            this->algorithm = algorithm;

            return *this;
        }
        
        DnskeyBuilder& setProtocol(uint8_t protocol) {
            this->protocol = protocol;

            return *this;
        }

        DnskeyBuilder& setPublicKey(const std::string &publicKey) {
            this->publicKey = publicKey;

            return *this;
        }

        DnskeyBuilder& setZoneKeyState() {
            flags = setBit(flags, 7);

            return *this;
        }

        DnskeyBuilder& setSecureEntryPointState() {
            flags = setBit(flags, 15);

            return *this;
        }
};

#endif // DNS64SEC_DNSKEY_BUILDER_H