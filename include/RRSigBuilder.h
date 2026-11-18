/**
 * @file RRSigBuilder.h
 * @author Andras Attila Gerendas
 * @brief Builder for an RRSig Resource Record
 * @version 0.1
 * @date 2026-10-23
 *
 * @copyright Copyright (c) 2026
 *
 */

#ifndef DNS64SEC_RR_SIG_BUILDER_H
#define DNS64SEC_RR_SIG_BUILDER_H

#include "OpensslDeleter.h"
#include "RRBuilder.h"

class RRSigBuilder : public RRBuilder {
    DnsMessage::RecordType typeCovered{0};
    uint8_t algorithm{0};
    uint8_t labels{0};
    uint32_t originalTtl{0};
    uint32_t signatureExpiration{0};
    uint32_t signatureInception{0};
    uint16_t keyTag{0};
    std::string signersName;
    std::string privateKey;
    std::vector<uint8_t> signature;

    public:
        RRSigBuilder(const std::string &name, DnsMessage::ClassType qclass = DnsMessage::ClassType::IN) : RRBuilder(name, DnsMessage::RecordType::RRSIG, qclass) {}

        virtual void buildBody(DnsMessage &target, uint16_t lengthLocation) override {
            target.addShort(static_cast<uint16_t>(typeCovered));
            target.addByte(algorithm);
            target.addByte(labels);
            target.addInteger(originalTtl);
            target.addInteger(signatureExpiration);
            target.addInteger(signatureInception);
            target.addShort(keyTag);
            target.generateName(signersName);
            target.setAnswerCount(target.getAnswerCount() + 1);
            addSignature(target, lengthLocation);
        }

        void addSignature(DnsMessage &target, uint16_t lengthLocation) {
            auto signatureBuffer = std::make_unique<uint8_t[]>(DnsMessage::MAX_LEN_SIG_BUFFER);

            uint16_t signatureAfterName = lengthLocation - 8;

            auto bufferPosition = target.generateSignature(signatureBuffer.get(), signatureAfterName, typeCovered);

            std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};

            EvpMdCtxPtr mdctx(EVP_MD_CTX_create());

            EVP_DigestInit_ex(mdctx.get(), EVP_sha256(), nullptr);
            EVP_DigestUpdate(mdctx.get(), signatureBuffer.get(), bufferPosition);
            EVP_DigestFinal_ex(mdctx.get(), digest.data(), nullptr);

            mdctx.reset();

            BioPtr bio(BIO_new_mem_buf(privateKey.data(), static_cast<int>(privateKey.size())));

            if (!bio) {
                return;
            }

            EvpPkeyPtr pkey(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));

            if (!pkey) {
                return;
            }

            EvpPkeyCtxPtr signContext(EVP_PKEY_CTX_new(pkey.get(), nullptr));

            if (signContext == nullptr) {
                return;
            }

            int result = EVP_PKEY_sign_init(signContext.get());

            if (result <= 0) {
                return;
            }

            result = EVP_PKEY_CTX_set_signature_md(signContext.get(), EVP_sha256());

            if (result <= 0) {
                return;
            }

            result = EVP_PKEY_CTX_set_rsa_padding(signContext.get(), RSA_PKCS1_PADDING);

            if (result <= 0) {
                return;
            }

            size_t sig_len = 0;

            if (EVP_PKEY_sign(signContext.get(), nullptr, &sig_len, &digest[0], digest.size()) <= 0) {
                return;
            }

            signature.clear();
            signature.resize(sig_len);

            if (EVP_PKEY_sign(signContext.get(), signature.data(), &sig_len, &digest[0], digest.size()) <= 0) {
                return;
            }

            signature.resize(sig_len);

            target.addBytes(&signature[0], signature.size());
        }

        RRSigBuilder& setTypeCovered(DnsMessage::RecordType typeCovered) {
            this->typeCovered = typeCovered;

            return *this;
        }

        RRSigBuilder& setAlgorithm(uint8_t algorithm) {
            this->algorithm = algorithm;

            return *this;
        }

        RRSigBuilder& setLabels(uint8_t labels) {
            this->labels = labels;

            return *this;
        }

        RRSigBuilder& setOriginalTtl(uint32_t originalTtl) {
            this->originalTtl = originalTtl;

            return *this;
        }

        RRSigBuilder& setPrivateKey(const std::string &privateKey) {
            this->privateKey = privateKey;

            return *this;
        }

        RRSigBuilder& setSignatureExpiration(uint32_t signatureExpiration) {
            this->signatureExpiration = signatureExpiration;

            return *this;
        }

        RRSigBuilder& setSignatureInception(uint32_t signatureInception) {
            this->signatureInception = signatureInception;

            return *this;
        }

        RRSigBuilder& setKeyTag(uint16_t keyTag) {
            this->keyTag = keyTag;

            return *this;
        }

        RRSigBuilder& setSignersName(const std::string &signersName) {
            this->signersName = signersName;

            return *this;
        }
};

#endif // DNS64SEC_RR_SIG_BUILDER_H