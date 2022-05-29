#pragma once

#include "Configuration.h"

#include <arpa/inet.h>
#include <cstring>
#include <memory>

constexpr auto BYTE_MASK = 0xFFU;
constexpr auto MASK_FIRST_UINT16_BIT = 0x8000U;
constexpr auto BYTE_SHIFT = 0x8U;
constexpr auto DNS_HEADER_LENGTH = 12U;

struct ExtendedRcode {
    uint16_t dnsHeaderPortion:4;
    uint16_t optRecordPortion:8;
    uint16_t padding:4; /* The 12-bit RCODE will be interpreted as a 16-bit number */
};

class DnsMessage {
        struct DnsHeader {
            uint16_t identifier;
            uint8_t recursionDesired:1;
            uint8_t truncated:1;
            uint8_t authoritative:1;
            uint8_t opcode:4;
            uint8_t isResponse:1;
            uint8_t responseCode:4;
            uint8_t checkingDisabled:1;
            uint8_t authenticatedData:1;
            uint8_t z:1;
            uint8_t recursionAvailable:1;
            uint16_t questionCount;
            uint16_t answerCount;
            uint16_t authorityCount;
            uint16_t additionalCount;
        };

        const std::unique_ptr<uint8_t> &buffer;
        const Configuration &configuration;
        uint16_t size{0};
        bool isValidB{false};

        bool isNonGlobalAddress(uint32_t addr) const;

    public:
        struct __attribute__((__packed__)) RrHeader {
            uint16_t type;
            uint16_t qclass;
            uint32_t ttl;
            uint16_t rdlength;
        };

        struct DnsKeyHeader {
            RrHeader header;
            /* TODO: Swapped the bit order, this wouldn't work on another architecture */
            uint8_t isZoneKey:1;
            uint8_t reservedThree:7;
            uint8_t isSecureEntryPoint:1;
            uint8_t reservedOne:7;
            uint8_t protocol;
            uint8_t algorithm;
        };

        struct __attribute__((__packed__)) RrSigRdata {
            uint16_t typeCovered;
            uint8_t algorithm;
            uint8_t labels;
            uint32_t originalTtl;
            uint32_t signatureExpiration;
            uint32_t signatureInception;
            uint16_t keyTag;
        };

        struct __attribute__((__packed__)) RrSigHeader {
            RrHeader header;
            RrSigRdata rdata;
        };

        enum class QrType {
            REQUEST = 0,
            RESPONSE = 1
        };

        enum class SectionType {
            QUESTION = 0,
            ANSWER = 1,
            AUTHORITY = 2,
            ADDITIONAL = 3
        };

        enum class RecordType : uint16_t {
            NO_VALUE = 0, /* can be used for other purposes, as it is reserved */
            A = 1,
            NS = 2,
            CNAME = 5,
            SOA = 6,
            PTR = 12,
            MX = 15,
            TXT = 16,
            RP = 17,
            AFSDB = 18,
            SIG = 24,
            KEY = 25,
            AAAA = 28,
            LOC = 29,
            SRV = 33,
            NAPTR = 35,
            KX = 36,
            CERT = 37,
            DNAME = 39,
            OPT = 41,
            APL = 42,
            DS = 43,
            SSHFP = 44,
            IPSECKEY = 45,
            RRSIG = 46,
            NSEC = 47,
            DNSKEY = 48,
            DHCID = 49,
            NSEC3 = 50,
            NSEC3PARAM = 51,
            HIP = 55,
            SPF = 99,
            TKEY = 249,
            TSIG = 250,
            TA = 32768,
            DLV = 32769
        };

        enum class ResponseCode : uint16_t {
            NOERROR = 0,
            FORMERR = 1,
            SERVFAIL = 2,
            NXDOMAIN = 3,
            NOTIMP = 4,
            REFUSED = 5,
            YXDOMAIN = 6,
            XRRSET = 7,
            NOTAUTH = 8,
            NOTZONE = 9,
            BADVERS = 16
        };

        enum class ClassType : uint16_t {
            IN = 1
        };

        DnsMessage(const std::unique_ptr<uint8_t> &buffer, const Configuration &configuration, uint16_t size) : buffer(buffer), configuration(configuration), size(size) {}

        [[nodiscard]] auto getShortAt(uint16_t position) const {
            return htons(buffer.get()[position] | buffer.get()[position + 1] << BYTE_SHIFT);
        }

        void setShortAt(uint16_t position, uint16_t value) {
            uint16_t inNetworkOrder = htons(value);
            buffer.get()[position] = inNetworkOrder & BYTE_MASK;
            buffer.get()[position + 1] = (inNetworkOrder >> BYTE_SHIFT);
        }

        [[nodiscard]] auto getTransactionID() const -> uint16_t {
            return getShortAt(0);
        }

        void setTransactionID(uint16_t transactionID) {
            setShortAt(0, transactionID);
        }

        [[nodiscard]] auto getType() const -> QrType {
            return (getShortAt(2) & MASK_FIRST_UINT16_BIT) == 0 ? QrType::REQUEST : QrType::RESPONSE;
        }

        [[nodiscard]] auto isValid() const -> bool {
            return isValidB;
        }

        [[nodiscard]] auto isOpCodeValid() const -> bool {
            DnsHeader *header = (DnsHeader *)buffer.get();

            /* Only QUERY is handled */
            return 0 == header->opcode;
        }

        void setValidState(bool isValid) {
            isValidB = isValid;
        }

        bool validateQuestionSection(const DnsMessage &other) {
            /* TODO: Store this somewhere */
            auto nameEnd = other.getNamePosition(DNS_HEADER_LENGTH);

            if (0 == nameEnd) {
                return false;
            }

            uint16_t questionSize = nameEnd - DNS_HEADER_LENGTH + 4U;

            if (0 != memcmp(&buffer.get()[DNS_HEADER_LENGTH], &other.buffer.get()[DNS_HEADER_LENGTH], questionSize)) {
                return false;
            }

            return true;
        }

        [[nodiscard]] auto getQueryCount() const -> uint16_t {
            return getShortAt(4);
        }

        [[nodiscard]] auto getAnswerCount() const -> uint16_t {
            return getShortAt(6);
        }

        [[nodiscard]] auto getAuthorityCount() const -> uint16_t {
            return getShortAt(8);
        }

        [[nodiscard]] auto getAdditionalCount() const -> uint16_t {
            return getShortAt(10);
        }

        [[nodiscard]] auto getNamePosition(uint16_t position) const -> uint16_t {
            /* The value is a pointer */
            /* TODO: This also needs to be manipulated? */
            if ((buffer.get()[position] & 0xC0U) != 0) {
                if (getSize() < position + 2) {
                    return 0;
                }

                return position + 2;
            }

            /* A name is stored as length separated strings until a zero */
            while (buffer.get()[position] > 0) {
                if (getSize() < buffer.get()[position] + 1U) {
                    return 0;
                }

                position += buffer.get()[position] + 1;
            }

            if (getSize() < position + 1) {
                return 0;
            }

            position++;

            return position;
        }

        bool hasRecordType(SectionType type, RecordType recordType) const {
            return getRecordTypePosition(type, recordType).first > 0;
        }

        /* TODO: Store the section start indexes to speed up the search when searched multiple times */
        /* TODO: If a query was validated once, there's no need to check the size conformance */
        std::pair<uint16_t, uint16_t> getRecordTypePosition(SectionType type, RecordType recordType, uint16_t startPoint = 0) const {
            switch(type) {
                case SectionType::ANSWER:
                    if (0 == getAnswerCount()) {
                        return std::make_pair(0, 0);
                    }
                    break;
                case SectionType::AUTHORITY:
                    if (0 == getAuthorityCount()) {
                        return std::make_pair(0, 0);
                    }
                    break;
                case SectionType::ADDITIONAL:
                    if (0 == getAdditionalCount()) {
                        return std::make_pair(0, 0);
                    }
                    break;
                default:
                    break;
            }

            uint16_t newPosition = DNS_HEADER_LENGTH;

            if (getSize() < newPosition) {
                return std::make_pair(0, 0);
            }

            for (uint16_t i = 0; i < getQueryCount(); i++) {
                uint16_t startPosition = newPosition;
                uint16_t position = getNamePosition(newPosition);

                if (position == 0) {
                    return std::make_pair(0, 0);
                }

                newPosition = position + 4;

                if (getSize() < newPosition) {
                    return std::make_pair(0, 0);
                }

                if (startPoint < startPosition && SectionType::QUESTION == type && recordType == getRecordType(position)) {
                    return std::make_pair(startPosition, position);
                }
            }

            if (SectionType::QUESTION == type) {
                return std::make_pair(0, 0);
            }

            for (uint16_t i = 0; i < getAnswerCount(); i++) {
                uint16_t startPosition = newPosition;
                uint16_t position = getNamePosition(newPosition);

                if (position == 0) {
                    return std::make_pair(0, 0);
                }

                newPosition = position + 10U;

                if (getSize() < newPosition) {
                    return std::make_pair(0, 0);
                }

                newPosition += getShortAt(newPosition - 2);

                if (getSize() < newPosition) {
                    return std::make_pair(0, 0);
                }

                if (startPoint < startPosition && SectionType::ANSWER == type && getRecordType(position) == recordType) {
                    return std::make_pair(startPosition, position);
                }
            }

            if (SectionType::ANSWER == type) {
                return std::make_pair(0, 0);
            }

            for (uint16_t i = 0; i < getAuthorityCount(); i++) {
                uint16_t startPosition = newPosition;
                uint16_t position = getNamePosition(newPosition);

                if (position == 0) {
                    return std::make_pair(0, 0);
                }

                newPosition = position + 10U;

                if (getSize() < newPosition) {
                    return std::make_pair(0, 0);
                }

                newPosition += getShortAt(newPosition - 2);

                if (getSize() < newPosition) {
                    return std::make_pair(0, 0);
                }

                if (startPoint < startPosition && SectionType::AUTHORITY == type && getRecordType(position) == recordType) {
                    return std::make_pair(startPosition, position);
                }
            }

            if (SectionType::AUTHORITY == type) {
                return std::make_pair(0, 0);
            }

            for (uint16_t i = 0; i < getAdditionalCount(); i++) {
                uint16_t startPosition = newPosition;
                uint16_t position = getNamePosition(newPosition);

                if (position == 0) {
                    return std::make_pair(0, 0);
                }

                newPosition = position + 10U;

                if (getSize() < newPosition) {
                    return std::make_pair(0, 0);
                }

                newPosition += getShortAt(newPosition - 2);

                if (getSize() < newPosition) {
                    return std::make_pair(0, 0);
                }

                if (startPoint < startPosition && SectionType::ADDITIONAL == type && getRecordType(position) == recordType) {
                    return std::make_pair(startPosition, position);
                }
            }

            return std::make_pair(0, 0);
        }

        [[nodiscard]] auto getRecordType(uint16_t position) const -> RecordType {
            return static_cast<RecordType>(getShortAt(position));
        }

        [[nodiscard]] auto getClassType(uint16_t position) const -> ClassType {
            return static_cast<ClassType>(getShortAt(position));
        }

        void setRecordType(uint16_t position, RecordType type) {
            uint16_t type_uint = htons(static_cast<uint16_t>(type));

            buffer.get()[position] = type_uint & BYTE_MASK;
            buffer.get()[position + 1] = (type_uint >> BYTE_SHIFT);
        }

        auto getQueryType(RecordType &type) const -> bool {
            uint16_t newPosition = DNS_HEADER_LENGTH;

            if (getSize() < newPosition) {
                return false;
            }

            uint16_t position = getNamePosition(newPosition);

            if (position == 0) {
                return false;
            }

            newPosition = position + 4;

            if (getSize() < newPosition) {
                return false;
            }

            type = static_cast<RecordType>(getShortAt(position));

            return true;
        }

        bool setQueryType(RecordType newType) {
            uint16_t newPosition = DNS_HEADER_LENGTH;

            if (getSize() < newPosition) {
                return false;
            }

            for (uint16_t i = 0; i < getQueryCount(); i++) {
                uint16_t position = getNamePosition(newPosition);

                if (position == 0) {
                    return false;
                }

                newPosition = position + 4;

                if (getSize() < newPosition) {
                    return false;
                }

                setRecordType(position, newType);
            }

            return true;
        }

        [[nodiscard]] auto getBuffer() const -> const std::unique_ptr<uint8_t>& {
            return buffer;
        }

        [[nodiscard]] auto getSize() const -> uint16_t {
            return size;
        }

        void modifyQueryToBeResponse(ResponseCode code) {
            DnsHeader *header = (DnsHeader *)buffer.get();

            header->isResponse = 1;

            if ((uint16_t)code < 16) {
                header->responseCode = (uint8_t) code;
            } else {
                auto [start, afterName] = getRecordTypePosition(DnsMessage::SectionType::ADDITIONAL, DnsMessage::RecordType::OPT);
                
                if (0 == start) {
                    header->responseCode = (uint16_t) ResponseCode::FORMERR;
                } else {
                    uint16_t codeValue = (uint16_t) code;
                    ExtendedRcode *extendedRcode = (ExtendedRcode*) &codeValue;

                    header->responseCode = extendedRcode->dnsHeaderPortion;
                    buffer.get()[afterName + 4] = extendedRcode->optRecordPortion;
                }
            }
        }

        [[nodiscard]] auto generateSynthetisedMessage(const std::unique_ptr<uint8_t> &buffer, uint16_t buffer_size, const struct in6_addr &dns64_prefix) const -> DnsMessage;

        uint16_t updateUdpPayloadSize(DnsMessage::ResponseCode &rcode) {
            /* TODO: Make EDNS support optional, to increase performance? */
            auto [start, afterName] = getRecordTypePosition(DnsMessage::SectionType::ADDITIONAL, DnsMessage::RecordType::OPT);

            /* TODO: Add an OPT record if necessary */
            if (0 == start) {
                return 512; /* There's no EDNS, so there's no need for a larger buffer */
            }

            auto [start2, afterName2] = getRecordTypePosition(DnsMessage::SectionType::ADDITIONAL, DnsMessage::RecordType::OPT, start);

            /* There are multiple OPT records */
            if (0 != start2) {
                rcode = DnsMessage::ResponseCode::FORMERR;
                return 0;
            }

            /* Checking if EDNS version is supported */
            if (buffer.get()[afterName + 5] > 0) {
                rcode = DnsMessage::ResponseCode::BADVERS;
                return 0;
            }

            uint16_t currentSize = getShortAt(afterName + 2);

            if (currentSize > configuration.getUdpPayloadSize()) {
                setShortAt(afterName + 2, configuration.getUdpPayloadSize());

                return configuration.getUdpPayloadSize();
            }

            if (currentSize < 512) {
                setShortAt(afterName + 2, 512);

                currentSize = 512;
            }

            return currentSize;
        }

        bool validateRrSigTimestamp(uint16_t position) {
            RrSigHeader *header = getRrsigHeader(position);

            time_t timestamp = time(NULL);

            int result = (int32_t) ((uint32_t)htonl(header->rdata.signatureInception) - (uint32_t)timestamp);

            if (result > 0) {
                return false;
            }

            result = (int32_t) ((uint32_t)timestamp - (uint32_t)htonl(header->rdata.signatureExpiration));

            return result < 0;
        }

        bool validateRrSigTypeCovered(uint16_t position, RecordType type) {
            RrSigHeader *header = getRrsigHeader(position);

            return htons(header->rdata.typeCovered) == static_cast<uint16_t>(type);
        }

        auto getRrsigHeader(uint16_t position) -> RrSigHeader* {
            return (RrSigHeader *)&buffer.get()[position];
        }

        auto getDnsKeyHeader(uint16_t position) -> DnsKeyHeader* {
            return (DnsKeyHeader *)&buffer.get()[position];
        }

        auto getRrHeader(uint16_t position) -> RrHeader* {
            return (RrHeader *)&buffer.get()[position];
        }

        auto calculateKeyTag(uint16_t position) -> uint16_t {
            auto start = &buffer.get()[position];

            /* Taken from RFC 4034 */

            unsigned long ac;
            int i;

            auto length = getShortAt(position + 8);

            for (ac = 0, i = 0; i < length; ++i) {
                ac += (i & 1) ? start[i + 10U] : start[i + 10U] << 8;
            }
            ac += (ac >> 16) & 0xFFFF;

            return ac & 0xFFFF;
        }
};