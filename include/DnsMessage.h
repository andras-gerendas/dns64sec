/**
 * @file DnsMessage.h
 * @author Andras Attila Gerendas
 * @brief Class representing a DNS message
 * @version 0.1
 * @date 2022-06-21
 *
 * @copyright Copyright (c) 2022
 *
 */

#pragma once

#include "Configuration.h"

#include <arpa/inet.h>
#include <cstring>
#include <memory>

/**
 * @brief Helper structure for the 12-bit RCODE (DNS header + OPT record)
 *
 */
struct __attribute__((__packed__)) ExtendedRcode {
    uint16_t dnsHeaderPortion:4;
    uint16_t optRecordPortion:8;
    uint16_t padding:4; /* The 12-bit RCODE will be interpreted as a 16-bit number */
};

class DnsMessage {
        /**
         * @brief Helper structure for the binary representation of a DNS header
         *
         */
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

        /**
         * @brief The buffer containing the currently used DNS message
         *
         */
        uint8_t *buffer;

        /**
         * @brief The size of the buffer containing the currently used DNS message
         *
         */
        uint16_t size;

        /**
         * @brief Helper function to calculate whether an address is a non-global IPv4 address
         *
         * @param addr The address to be checked
         * @return true The address is a non-global IPv4 address
         * @return false The address is a global IPv4 address
         */
        [[nodiscard]] static auto isNonGlobalAddress(uint32_t addr) -> bool;

    public:
        /**
         * @brief The mask for separating the lower 8-bits of a 16-bit integer
         *
         */
        static inline constexpr uint16_t BYTE_MASK = 0xFFU;

        /**
         * @brief Mask for separating the first bit of a 16-bit integer
         *
         */
        static inline constexpr uint16_t MASK_FIRST_UINT16_BIT = 0x8000U;

        /**
         * @brief The shift value to bit shift a byte
         *
         */
        static inline constexpr uint8_t BYTE_SHIFT = 0x8U;

        /**
         * @brief The length of the fixed-length DNS header
         *
         */
        static inline constexpr uint16_t DNS_HEADER_LENGTH = 12U;

        /**
         * @brief The maximum size of the RRSIG signature buffer
         *
         */
        static inline constexpr uint16_t MAX_LEN_SIG_BUFFER = 8192U;

        /**
         * @brief The length of the fixed portion of an RR
         *
         */
        static inline constexpr uint16_t LEN_RR_FIXED = 10U;

        /**
         * @brief The length of the fixed portion of an RRSIG RDATA
         *
         */
        static inline constexpr uint16_t LEN_RRSIG_RDATA_FIXED = 18U;

        /**
         * @brief The length of the fixed portion of an RRSIG RR
         *
         */
        static inline constexpr uint16_t LEN_RRSIG_FIXED = LEN_RR_FIXED + LEN_RRSIG_RDATA_FIXED;

        /**
         * @brief The bitmask for identifying a pointer
         *
         */
        static inline constexpr uint8_t MASK_POINTER = 0xC0U;

        /**
         * @brief The first extended RCODE
         *
         */
        static inline constexpr uint8_t FIRST_EXTENDED_RCODE = 16U;

        /**
         * @brief Helper structure for the binary representation of the fixed-portion of an RR
         *
         */
        struct __attribute__((__packed__)) RrHeader {
            uint16_t type;
            uint16_t qclass;
            uint32_t ttl;
            uint16_t rdlength;
        };

        /**
         * @brief Helper structure for the binary representation of a DNSKEY RR
         *
         */
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

        /**
         * @brief Helper structure for the binary representation of an RRSIG RDATA
         *
         */
        struct __attribute__((__packed__)) RrSigRdata {
            uint16_t typeCovered;
            uint8_t algorithm;
            uint8_t labels;
            uint32_t originalTtl;
            uint32_t signatureExpiration;
            uint32_t signatureInception;
            uint16_t keyTag;
        };

        /**
         * @brief Helper structure for the binary representation of an RRSIG RR
         *
         */
        struct __attribute__((__packed__)) RrSigHeader {
            RrHeader header;
            RrSigRdata rdata;
        };

        /**
         * @brief The value of the QR part of the DNS header (whether the current message is a request or a response)
         *
         */
        enum class QrType {
            REQUEST = 0,
            RESPONSE = 1
        };

        /**
         * @brief The section of the DNS message
         *
         */
        enum class SectionType {
            QUESTION = 0,
            ANSWER = 1,
            AUTHORITY = 2,
            ADDITIONAL = 3
        };

        /**
         * @brief The type of the RR in a DNS message
         *
         */
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

        /**
         * @brief The response code of a DNS message (includes extended RCODEs)
         *
         */
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

        /**
         * @brief The type of the RR class
         *
         */
        enum class ClassType : uint16_t {
            IN = 1
        };

        /**
         * @brief Construct a new Dns Message object
         *
         * @param buffer The buffer containing the currently used DNS message
         * @param size The size of the buffer containing the currently used DNS message
         */
        DnsMessage(uint8_t *buffer, uint16_t size) : buffer(buffer), size(size) {}

        /**
         * @brief Converts a 16-bit integer from network order to host order
         *
         * @param position The starting position of the 16-bit integer
         * @return auto The value in host order
         */
        [[nodiscard]] auto getShortAt(uint16_t position) const {
            return htons(buffer[position] | buffer[position + 1] << BYTE_SHIFT);
        }

        /**
         * @brief Converts a 16-bit integer from host order to network order
         *
         * @param position The starting position of the 16-bit integer
         * @param value The value in host order
         */
        void setShortAt(uint16_t position, uint16_t value) {
            uint16_t inNetworkOrder = htons(value);
            buffer[position] = inNetworkOrder & BYTE_MASK;
            buffer[position + 1] = (inNetworkOrder >> BYTE_SHIFT);
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

        [[nodiscard]] auto isOpCodeValid() const -> bool {
            auto *header = reinterpret_cast<DnsHeader *>(buffer);

            /* Only QUERY is handled */
            return 0 == header->opcode;
        }

        /**
         * @brief Compares the question section of two DNS messages
         *
         * @param other The other DNS message
         * @return true The two question sections are equal
         * @return false The two question sections differ
         */
        auto validateQuestionSection(const DnsMessage &other) -> bool {
            /* TODO: Store this somewhere */
            auto nameEnd = other.getNamePosition(DNS_HEADER_LENGTH);

            if (0 == nameEnd) {
                return false;
            }

            uint16_t questionSize = nameEnd - DNS_HEADER_LENGTH + 4U;

            return 0 == memcmp(&buffer[DNS_HEADER_LENGTH], &other.buffer[DNS_HEADER_LENGTH], questionSize);
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

        /**
         * @brief Calculates the end position of a list of labels
         *
         * @param position The starting position of the list of labels
         * @return uint16_t The position at the end of the list of labels
         */
        [[nodiscard]] auto getNamePosition(uint16_t position) const -> uint16_t {
            /* The value is a pointer */
            /* TODO: This also needs to be manipulated? */
            if ((buffer[position] & MASK_POINTER) != 0) {
                if (getSize() < position + 2) {
                    return 0;
                }

                return position + 2;
            }

            /* A name is stored as length separated strings until a zero */
            while (buffer[position] > 0) {
                if (getSize() < buffer[position] + 1U) {
                    return 0;
                }

                position += buffer[position] + 1;
            }

            if (getSize() < position + 1) {
                return 0;
            }

            position++;

            return position;
        }

        /**
         * @brief Returns whether the section has at least one valid specified RR
         *
         * @param type The section to be examined
         * @param recordType The RR type being searched
         * @return true At least one RR is in the section
         * @return false There are such no valid RRs in the section
         */
        [[nodiscard]] auto hasRecordType(SectionType type, RecordType recordType) const -> bool {
            return getRecordTypePosition(type, recordType).first > 0;
        }

        /* TODO: Store the section start indexes to speed up the search when searched multiple times */
        /* TODO: If a query was validated once, there's no need to check the size conformance */
        /**
         * @brief Returns the beginning and the end of the list of labels of an RR, or zero for both values if a valid RR cannot be found
         *
         * @param type The section to be examined
         * @param recordType The RR type being searched
         * @param startPoint The position where the search is started (allows an iteration of the records)
         * @return std::pair<uint16_t, uint16_t> The beginning and the end position of the list of labels of the RR, or zero for both values if a valid RR cannot be found
         */
        [[nodiscard]] auto getRecordTypePosition(SectionType type, RecordType recordType, uint16_t startPoint = 0) const -> std::pair<uint16_t, uint16_t> {
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

                newPosition = position + LEN_RR_FIXED;

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

                newPosition = position + LEN_RR_FIXED;

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

                newPosition = position + LEN_RR_FIXED;

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

            buffer[position] = type_uint & BYTE_MASK;
            buffer[position + 1] = (type_uint >> BYTE_SHIFT);
        }

        auto getQueryType(RecordType *type) const -> bool {
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

            *type = static_cast<RecordType>(getShortAt(position));

            return true;
        }

        auto setQueryType(RecordType newType) -> bool {
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

        [[nodiscard]] auto getBuffer() const -> uint8_t* {
            return buffer;
        }

        [[nodiscard]] auto getSize() const -> uint16_t {
            return size;
        }

        /**
         * @brief Modifies a DNS query to be a response with the RCODE specified as a parameter (supports extended RCODEs)
         *
         * @param code The response code to be set
         */
        void modifyQueryToBeResponse(ResponseCode code) {
            auto *header = reinterpret_cast<DnsHeader *>(buffer);

            header->isResponse = 1;

            if (static_cast<uint16_t>(code) < FIRST_EXTENDED_RCODE) {
                header->responseCode = static_cast<uint8_t>(code);
            } else {
                auto [start, afterName] = getRecordTypePosition(DnsMessage::SectionType::ADDITIONAL, DnsMessage::RecordType::OPT);

                if (0 == start) {
                    header->responseCode = static_cast<uint16_t>(ResponseCode::FORMERR);
                } else {
                    auto codeValue = static_cast<uint16_t>(code);
                    auto *extendedRcode = reinterpret_cast<ExtendedRcode*>(&codeValue);

                    header->responseCode = extendedRcode->dnsHeaderPortion;
                    buffer[afterName + 4] = extendedRcode->optRecordPortion;
                }
            }
        }

        /**
         * @brief Generates the synthesised IPv6 addresses for found IPv4 addresses
         *
         * @param configuration The current configuration instance
         * @param message The message to be manipulated
         * @return true The synthesis could successfully be performed
         * @return false There was an issue during the synthesis (buffer length issue or well-known prefix with non-global address)
         */
        [[nodiscard]] auto generateSynthetisedMessage(const Configuration &configuration, DnsMessage *message) const -> bool;

        /**
         * @brief Adjusts the UDP payload size to the minimum of the current message and the configured value (but at least MAX_NON_EDNS_PACKET bytes)
         *
         * @param configuration The current configuration instance
         * @param rcode A buffer where the response code can be stored if a failure occurs (FORMERR, BADVERS)
         * @return uint16_t The size of the UDP payload size parameter after the adjustment, or zero if an error occurs
         */
        auto updateUdpPayloadSize(const Configuration &configuration, DnsMessage::ResponseCode *rcode) -> uint16_t {
            /* TODO: Make EDNS support optional, to increase performance? */
            auto [start, afterName] = getRecordTypePosition(DnsMessage::SectionType::ADDITIONAL, DnsMessage::RecordType::OPT);

            /* TODO: Add an OPT record if necessary */
            if (0 == start) {
                return Configuration::MAX_NON_EDNS_PACKET; /* There's no EDNS, so there's no need for a larger buffer */
            }

            auto [start2, afterName2] = getRecordTypePosition(DnsMessage::SectionType::ADDITIONAL, DnsMessage::RecordType::OPT, start);

            /* There are multiple OPT records */
            if (0 != start2) {
                *rcode = DnsMessage::ResponseCode::FORMERR;
                return 0;
            }

            /* Checking if EDNS version is supported */
            if (buffer[afterName + 5] > 0) {
                *rcode = DnsMessage::ResponseCode::BADVERS;
                return 0;
            }

            uint16_t currentSize = getShortAt(afterName + 2);

            if (currentSize > configuration.getUdpPayloadSize()) {
                setShortAt(afterName + 2, configuration.getUdpPayloadSize());

                return configuration.getUdpPayloadSize();
            }

            if (currentSize < Configuration::MAX_NON_EDNS_PACKET) {
                setShortAt(afterName + 2, Configuration::MAX_NON_EDNS_PACKET);

                currentSize = Configuration::MAX_NON_EDNS_PACKET;
            }

            return currentSize;
        }

        /**
         * @brief Validates the RRSIG timestamp based on the serial number arithmetic
         *
         * @param position The position where the RRSIG RR can be found
         * @return true The RRSIG timestamp is valid
         * @return false The RRSIG timestamp is invalid
         */
        auto validateRrSigTimestamp(uint16_t position) -> bool {
            auto *header = getRrsigHeader(position);

            time_t timestamp = time(nullptr);

            int result = (int32_t) ((uint32_t)htonl(header->rdata.signatureInception) - (uint32_t)timestamp);

            if (result > 0) {
                return false;
            }

            result = (int32_t) ((uint32_t)timestamp - (uint32_t)htonl(header->rdata.signatureExpiration));

            return result < 0;
        }

        /**
         * @brief Validates whether the type of the current DNS message is covered by the RRSIG
         *
         * @param position The position where the RRSIG RR can be found
         * @param type The type of the record to be checked
         * @return true The type is present in the RRSIG
         * @return false The type is not present in the RRSIG
         */
        auto validateRrSigTypeCovered(uint16_t position, RecordType type) -> bool {
            auto *header = getRrsigHeader(position);

            return htons(header->rdata.typeCovered) == static_cast<uint16_t>(type);
        }

        auto getRrsigHeader(uint16_t position) -> RrSigHeader* {
            return reinterpret_cast<RrSigHeader *>(&buffer[position]);
        }

        auto getDnsKeyHeader(uint16_t position) -> DnsKeyHeader* {
            return reinterpret_cast<DnsKeyHeader *>(&buffer[position]);
        }

        auto getRrHeader(uint16_t position) -> RrHeader* {
            return reinterpret_cast<RrHeader *>(&buffer[position]);
        }

        /**
         * @brief Calculates the DNSKEY key tag according to RFC 4034
         *
         * @param position The position where the DNSKEY RDATA can be found
         * @return uint16_t The calculated key tag
         */
        auto calculateKeyTag(uint16_t position) -> uint16_t {
            auto *start = &buffer[position];

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