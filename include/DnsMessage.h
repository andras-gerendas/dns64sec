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

#ifndef DNS64SEC_DNS_MESSAGE_H
#define DNS64SEC_DNS_MESSAGE_H

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
         * @brief The buffer containing the currently used DNS message
         *
         */
        std::unique_ptr<uint8_t[]> buffer{nullptr};

        uint16_t capacity{0};

        /**
         * @brief The size of the buffer containing the currently used DNS message
         *
         */
        uint16_t size{0};

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
        static constexpr uint16_t BYTE_MASK = 0xFFU;

        /**
         * @brief The mask for separating the lower 16-bits of a 32-bit integer
         * 
         */
        static constexpr uint32_t LONG_BYTE_MASK = 0xFFFFU;

        /**
         * @brief Mask for separating the first bit of a 16-bit integer
         *
         */
        static constexpr uint16_t MASK_FIRST_UINT16_BIT = 0x8000U;

        /**
         * @brief The shift value to bit shift a byte
         *
         */
        static constexpr uint8_t BYTE_SHIFT = 0x8U;

        /**
         * @brief The shift value to bit shift two bytes
         * 
         */
        static constexpr uint16_t TWO_BYTE_SHIFT = 0x10U;

        /**
         * @brief The length of the fixed-length DNS header
         *
         */
        static constexpr uint16_t DNS_HEADER_LENGTH = 12U;

        /**
         * @brief The maximum size of the RRSIG signature buffer
         *
         */
        static constexpr uint16_t MAX_LEN_SIG_BUFFER = 8192U;

        /**
         * @brief Length of an IPv4 address
         * 
         */
        static constexpr uint8_t LEN_IPV4_ADDR = 4U;

        /**
         * @brief Length of an IPv6 address
         * 
         */
        static constexpr uint8_t LEN_IPV6_ADDR = 16U;

        /**
         * @brief The length of the fixed portion of an RR
         *
         */
        static constexpr uint16_t LEN_RR_FIXED = 10U;

        /**
         * @brief The length of the fixed portion of an RRSIG RDATA
         *
         */
        static constexpr uint16_t LEN_RRSIG_RDATA_FIXED = 18U;

        /**
         * @brief The length of the fixed portion of a SOA RDATA
         *
         */
        static constexpr uint16_t LEN_SOA_RDATA_FIXED = 20U;

        /**
         * @brief The length of the fixed portion of a DS RDATA
         * 
         */
        static constexpr uint16_t LEN_DS_RDATA_FIXED = 4U;

        /**
         * @brief The length of the fixed portion of an RRSIG RR
         *
         */
        static constexpr uint16_t LEN_RRSIG_FIXED = LEN_RR_FIXED + LEN_RRSIG_RDATA_FIXED;

        /**
         * @brief The bitmask for identifying a pointer
         *
         */
        static constexpr uint8_t COMPRESSION_POINTER_TAG = 0xC0U;

        /**
         * @brief The bitmask for name compression offset
         * 
         */
        static constexpr uint8_t COMPRESSION_OFFSET_MASK = 0x3FU;

        /**
         * @brief The first extended RCODE
         *
         */
        static constexpr uint8_t FIRST_EXTENDED_RCODE = 16U;

        /**
         * @brief Location of the Query Count field from the start of the DNS header
         * 
         */
        static constexpr uint16_t QUERY_COUNT_LOCATION = 4U;

        /**
         * @brief Location of the Answer Count field from the start of the DNS header
         * 
         */
        static constexpr uint16_t ANSWER_COUNT_LOCATION = 6U;

        /**
         * @brief Location of the Authority Count field from the start of the DNS header
         * 
         */
        static constexpr uint16_t AUTHORITY_COUNT_LOCATION = 8U;

        /**
         * @brief Location of the Additional Count field from the start of the DNS header
         * 
         */
        static constexpr uint16_t ADDITIONAL_COUNT_LOCATION = 10U;

        static constexpr uint8_t IPV4_ADDR_THREE_BYTE = 3U;
        static constexpr uint8_t IPV4_ADDR_ONE_BYTE = 1U;
        static constexpr uint8_t IPV4_ADDR_HALF = 2U;
        static constexpr uint8_t PREFIX_32_BIT = 32U;
        static constexpr uint8_t PREFIX_40_BIT = 40U;
        static constexpr uint8_t PREFIX_40_BIT_PREFIX = 5U;
        static constexpr uint8_t PREFIX_40_BIT_SUFFIX = 9U;
        static constexpr uint8_t PREFIX_48_BIT = 48U;
        static constexpr uint8_t PREFIX_48_BIT_PREFIX = 6U;
        static constexpr uint8_t PREFIX_48_BIT_SUFFIX = 9U;
        static constexpr uint8_t PREFIX_56_BIT = 56U;
        static constexpr uint8_t PREFIX_56_BIT_PREFIX = 7U;
        static constexpr uint8_t PREFIX_56_BIT_SUFFIX = 9U;
        static constexpr uint8_t PREFIX_64_BIT = 64U;
        static constexpr uint8_t PREFIX_64_BIT_PREFIX = 9U;
        static constexpr uint8_t PREFIX_96_BIT = 96U;
        static constexpr uint8_t PREFIX_96_BIT_PREFIX = 12U;

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
         * @brief Helper structure for the binary representation of the fixed-portion of an RR
         *
         */
        struct __attribute__((__packed__)) RrHeader {
            uint16_t type;
            uint16_t qclass;
            uint32_t ttl;
            uint16_t rdlength;

            [[nodiscard]] auto getLength() const -> uint16_t {
                return ntohs(rdlength);
            }
        };

        struct __attribute__((__packed__)) OptRecord {
            uint16_t type;
            uint16_t udpPayloadSize;
            uint8_t extendedRcode;
            uint8_t version;
            uint16_t flags;
            uint16_t rdlength;

            [[nodiscard]] auto getUdpPayloadSize() const -> uint16_t {
                return ntohs(udpPayloadSize);
            }
        };

        /**
         * @brief Helper structure for the binary representation of a DNSKEY RR
         *
         */
        struct __attribute__((__packed__)) DnsKeyHeader {
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

            [[nodiscard]] auto getKeyTag() const -> uint16_t {
                return ntohs(keyTag);
            }

            [[nodiscard]] auto getTypeCovered() const -> uint16_t {
                return ntohs(typeCovered);
            }
        };

        /**
         * @brief Helper structure for the binary representation of an RRSIG RR
         *
         */
        struct __attribute__((__packed__)) RrSigHeader {
            RrHeader header;
            RrSigRdata rdata;
        };

        struct __attribute__((__packed__)) DsRdata {
            uint16_t keyTag;
            uint8_t algorithm;
            uint8_t digestType;

            [[nodiscard]] auto getKeyTag() const -> uint16_t {
                return ntohs(keyTag);
            }
        };

        /**
         * @brief Helper structure for the binary representation of a DS RR
         *
         */
        struct __attribute__((__packed__)) DsHeader {
            RrHeader header;
            DsRdata rdata;
        };

        /**
         * @brief The value of the QR part of the DNS header (whether the current message is a request or a response)
         *
         */
        enum class QrType : uint8_t {
            REQUEST = 0,
            RESPONSE = 1
        };

        /**
         * @brief The section of the DNS message
         *
         */
        enum class SectionType : uint8_t {
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

        enum class KeyType : uint8_t {
            RSA_SHA256 = 8,
            ECDSA_SHA256 = 13
        };

        enum class DigestType : uint8_t {
            SHA256 = 2
        };

        enum class SignatureValidationResult : uint8_t {
            SUCCESS = 1,
            KEY_NOT_FOUND = 2,
            TYPE_COVERED_INVALID = 3,
            TIMESTAMP_INVALID = 4
        };

        class RecordParser {
            const DnsMessage &message;
            uint16_t position{0};
            uint16_t currentRecord{0};
            SectionType currentSection{SectionType::QUESTION};

            auto getNextSection(SectionType section) -> SectionType {
                switch(section) {
                    case SectionType::QUESTION:
                        return SectionType::ANSWER;
                    case SectionType::ANSWER:
                        return SectionType::AUTHORITY;
                    case SectionType::AUTHORITY:
                        return SectionType::ADDITIONAL;
                    default:
                        return SectionType::QUESTION;
                }
            }

            auto parseNextQuestion(SectionType section, RecordType recordType) -> std::pair<uint16_t, uint16_t> {
                const uint16_t startPosition = position;
                const uint16_t afterName = message.getNamePosition(startPosition);

                if (afterName == 0) {
                    return {0U, 0U};
                }

                const uint16_t newPosition = afterName + 4U;

                if (message.getSize() < newPosition) {
                    return {0U, 0U};
                }

                position = newPosition;
                currentRecord++;

                if (SectionType::QUESTION == section && recordType == message.getRecordType(afterName)) {
                    return {startPosition, afterName};
                }

                return {0U, 0U};
            }

            auto parseNextRecord(SectionType section, SectionType currentSection, RecordType recordType) -> std::pair<uint16_t, uint16_t> {
                const uint16_t startPosition = position;
                const uint16_t afterName = message.getNamePosition(startPosition);

                const uint16_t newPosition = message.getRecordEnd(afterName);

                if (0U == newPosition) {
                    return {0U, 0U};
                }

                position = newPosition;
                currentRecord++;

                if (section == currentSection && message.getRecordType(afterName) == recordType) {
                    return {startPosition, afterName};
                }

                return {0U, 0U};
            }

        public:
            explicit RecordParser(const DnsMessage &message) : message(message) {}

            /* TODO: Store the section start indexes to speed up the search when searched multiple times */
            /* TODO: If a query was validated once, there's no need to check the size conformance */
            /**
             * @brief Returns the beginning and the end of the list of labels of an RR, or zero for both values if a valid RR cannot be found
             *
             * @param section The section to be examined
             * @param recordType The RR type being searched
             * @return std::pair<uint16_t, uint16_t> The beginning and the end position of the list of labels of the RR, or zero for both values if a valid RR cannot be found
             */
            auto parseNext(SectionType section, RecordType record) -> std::pair<uint16_t, uint16_t> {
                if (0U == message.getSectionCount(section)) {
                    return {0U, 0U};
                }

                if (position == 0U) {
                    const uint16_t newPosition = DNS_HEADER_LENGTH;

                    if (message.getSize() < newPosition) {
                        return {0U, 0U};
                    }

                    position = newPosition;
                }

                if (currentSection == SectionType::QUESTION) {
                    for (uint16_t i = currentRecord; i < message.getSectionCount(SectionType::QUESTION); i++) {
                        auto result = parseNextQuestion(section, record);

                        if (result.second != 0U) {
                            return result;
                        }
                    }

                    currentSection = SectionType::ANSWER;
                    currentRecord = 0U;

                    if (section == SectionType::QUESTION) {
                        return {0U, 0U};
                    }
                }

                while(currentSection != SectionType::QUESTION) {
                    for (uint16_t i = currentRecord; i < message.getSectionCount(currentSection); i++) {
                        auto result = parseNextRecord(currentSection, section, record);

                        if (result.second != 0U) {
                            return result;
                        }
                    }

                    if (section == currentSection) {
                        currentSection = getNextSection(currentSection);
                        currentRecord = 0U;

                        return {0U, 0U};
                    }

                    currentSection = getNextSection(currentSection);
                    currentRecord = 0U;
                }

                return {0U, 0U};
            }

            void reset() {
                currentRecord = 0U;
                currentSection = SectionType::QUESTION;
                position = 0U;
            }
        };

        /**
         * @brief Construct an empty Dns Message object
         * 
         */
        DnsMessage() = default;

        explicit DnsMessage(uint16_t capacity, uint16_t size = 0U) : capacity(capacity), size(size) {
            buffer = std::make_unique<uint8_t[]>(capacity);
        }

        /**
         * @brief Construct a new Dns Message object
         *
         * @param buffer The buffer containing the currently used DNS message
         * @param size The size of the buffer containing the currently used DNS message
         */
        DnsMessage(std::unique_ptr<uint8_t[]> buffer, uint16_t capacity, uint16_t size = 0U) : buffer(std::move(buffer)), capacity(capacity), size(size) {}

        void addQuestion(const std::string &name, RecordType recordType = RecordType::AAAA, ClassType classType = ClassType::IN);
        auto addA(const std::string &ipv4, uint32_t ttl = 0U, const std::string &name = "inherit", ClassType classType = ClassType::IN) -> bool;
        auto addAAAA(const std::string &ipv6, uint32_t ttl = 0U, const std::string &name = "inherit", ClassType classType = ClassType::IN) -> bool;
        void addOPT(uint16_t udpPayloadSize = Configuration::MAX_NON_EDNS_PACKET, ResponseCode responseCode = ResponseCode::NOERROR, uint8_t version = 0U, bool dnssecOK = false);

        void addByte(uint8_t value) {
            buffer[size] = value;
            size++;
        }

        void addBytes(uint8_t *values, uint16_t length) {
            memcpy(&buffer[size], values, length);
            size += length;
        }

        void addShort(uint16_t value) {
            setShortAt(size, value);
            size += 2U;
        }

        void addInteger(uint32_t value) {
            (uint32_t&)buffer[size] = htonl(value);
            size += 4U;
        }

        void compressNames() const;

        void generateName(const std::string &name);

        [[nodiscard]] auto getResponseCode() const -> ResponseCode {
            auto [start, afterName] = RecordParser(*this).parseNext(DnsMessage::SectionType::ADDITIONAL, DnsMessage::RecordType::OPT);

            auto *header = reinterpret_cast<DnsHeader *>(buffer.get());

            if (0U == start) {
                return static_cast<ResponseCode>(header->responseCode);
            }

            uint16_t codeValue{};
            auto *extendedRcode = reinterpret_cast<ExtendedRcode*>(&codeValue);
            extendedRcode->dnsHeaderPortion = header->responseCode;
            extendedRcode->optRecordPortion = buffer[afterName + 4U];

            return static_cast<ResponseCode>(codeValue);
        }

        void updateBuffer(std::unique_ptr<uint8_t[]> buffer, uint16_t capacity) {
            this->buffer = std::move(buffer);
            this->capacity = capacity;
        }

        [[nodiscard]] auto compareLabelListsName(uint16_t firstStart, uint16_t secondStart) const -> int;

        [[nodiscard]] auto compareLabelListsBinary(uint16_t firstStart, uint16_t secondStart) const -> int;

        void copyBuffer(DnsMessage *target) const;

        [[nodiscard]] auto copyLabelListAsParent(DnsMessage *target) const -> bool;

        [[nodiscard]] auto expandName(uint8_t *signatureBuffer, uint16_t bufferPosition, uint16_t position) const -> size_t;

        [[nodiscard]] auto followPointer(uint16_t position) const -> uint16_t {
            while (true) {
                if ((buffer[position] & COMPRESSION_POINTER_TAG) == COMPRESSION_POINTER_TAG) {
                    if (getSize() < position + 2U) {
                        return 0U;
                    }

                    position = static_cast<uint16_t>(
                        (static_cast<uint32_t>(buffer[position] & COMPRESSION_OFFSET_MASK) << BYTE_SHIFT)
                        | static_cast<uint32_t>(buffer[position + 1U]));
                }

                break;
            }

            return position;
        }

        [[nodiscard]] auto generateSignature(uint8_t *signatureBuffer, uint16_t rrsigAfterName, RecordType queryType) const -> size_t;

        /**
         * @brief Converts a 16-bit integer from network order to host order
         *
         * @param position The starting position of the 16-bit integer
         * @return auto The value in host order
         */
        [[nodiscard]] auto getShortAt(uint16_t position) const -> uint16_t {
            return static_cast<uint16_t>(
                (static_cast<uint32_t>(buffer[position]) << BYTE_SHIFT
                | static_cast<uint32_t>(buffer[position + 1U])));
        }

        /**
         * @brief Converts a 32-bit integer from network order to host order
         *
         * @param position The starting position of the 32-bit integer
         * @return auto The value in host order
         */
        [[nodiscard]] auto getIntegerAt(uint16_t position) const -> uint32_t {
            return (static_cast<uint32_t>(buffer[position]) << (BYTE_SHIFT * 3U))
                    | (static_cast<uint32_t>(buffer[position + 1U]) << TWO_BYTE_SHIFT)
                    | (static_cast<uint32_t>(buffer[position + 2U]) << BYTE_SHIFT)
                    |  static_cast<uint32_t>(buffer[position + 3U]);
        }

        /**
         * @brief Converts a 16-bit integer from host order to network order
         *
         * @param position The starting position of the 16-bit integer
         * @param value The value in host order
         */
        void setShortAt(uint16_t position, uint16_t value) {
            const uint16_t inNetworkOrder = htons(value);
            buffer[position] = inNetworkOrder & BYTE_MASK;
            buffer[position + 1U] = (inNetworkOrder >> BYTE_SHIFT);
        }

        [[nodiscard]] auto getTransactionID() const -> uint16_t {
            return getShortAt(0U);
        }

        void setTransactionID(uint16_t transactionID) {
            setShortAt(0U, transactionID);
        }

        [[nodiscard]] auto getType() const -> QrType {
            return (getShortAt(2U) & MASK_FIRST_UINT16_BIT) == 0 ? QrType::REQUEST : QrType::RESPONSE;
        }

        [[nodiscard]] auto isOpCodeValid() const -> bool {
            auto *header = reinterpret_cast<DnsHeader *>(buffer.get());

            /* Only QUERY is handled */
            return 0U == header->opcode;
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
            const uint16_t questionSize = other.getFirstQuestionSize();

            if (questionSize == 0U) {
                return false;
            }

            return 0 == memcmp(&buffer[DNS_HEADER_LENGTH], &other.buffer[DNS_HEADER_LENGTH], questionSize);
        }

        [[nodiscard]] auto getFirstQuestionSize() const -> uint16_t {
            auto nameEnd = getNamePosition(DNS_HEADER_LENGTH);

            if (0U == nameEnd) {
                return 0U;
            }

            return nameEnd - DNS_HEADER_LENGTH + 4U;
        }

        [[nodiscard]] auto getQueryCount() const -> uint16_t {
            return getShortAt(QUERY_COUNT_LOCATION);
        }

        [[nodiscard]] auto getAnswerCount() const -> uint16_t {
            return getShortAt(ANSWER_COUNT_LOCATION);
        }

        [[nodiscard]] auto getAuthorityCount() const -> uint16_t {
            return getShortAt(AUTHORITY_COUNT_LOCATION);
        }

        [[nodiscard]] auto getAdditionalCount() const -> uint16_t {
            return getShortAt(ADDITIONAL_COUNT_LOCATION);
        }

        /**
         * @brief Calculates the end position of a list of labels
         *
         * @param position The starting position of the list of labels
         * @return uint16_t The position at the end of the list of labels
         */
        [[nodiscard]] auto getNamePosition(uint16_t position) const -> uint16_t {
            /* A name is stored as length separated strings until a zero */
            while (buffer[position] > 0) {
                /* A pointer always marks the end of the sequence */
                /* TODO: This also needs to be manipulated? */
                if ((buffer[position] & COMPRESSION_POINTER_TAG) == COMPRESSION_POINTER_TAG) {
                    if (getSize() < position + 2U) {
                        return 0U;
                    }

                    return position + 2U;
                }

                if (getSize() < buffer[position] + 1U) {
                    return 0U;
                }

                position += buffer[position] + 1U;
            }

            if (getSize() < position + 1U) {
                return 0U;
            }

            position++;

            return position;
        }

        [[nodiscard]] auto getNextLabel(uint16_t position) const -> uint16_t {
            if (buffer[position] == 0U) {
                return position;
            }

            position = followPointer(position);

            if (position == 0U) {
                return 0U;
            }

            if (getSize() < position + buffer[position] + 1U) {
                return 0U;
            }

            const uint16_t nextValue = followPointer(position + buffer[position] + 1U);

            if (nextValue == 0U) {
                return 0U;
            }

            return nextValue;
        }

        [[nodiscard]] auto getPreviousLabel(uint16_t position, uint16_t currentLabelPosition) const -> uint16_t {
            while(buffer[position] > 0U) {
                position = followPointer(position);

                if (position == 0U) {
                    return 0U;
                }

                if (getSize() < position + buffer[position] + 1U) {
                    return 0U;
                }

                const uint16_t nextValue = followPointer(position + buffer[position] + 1U);

                if (nextValue == 0U) {
                    return 0U;
                }

                if (position != currentLabelPosition && nextValue != currentLabelPosition && buffer[nextValue] != 0U) {
                    position += buffer[position] + 1U;
                } else {
                    return position;
                }
            }

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
            return RecordParser(*this).parseNext(type, recordType).first > 0U;
        }

        [[nodiscard]] auto getSectionCount(SectionType section) const -> uint16_t {
            switch (section) {
                case SectionType::QUESTION:
                    return getShortAt(QUERY_COUNT_LOCATION);
                case SectionType::ANSWER:
                    return getShortAt(ANSWER_COUNT_LOCATION);
                case SectionType::AUTHORITY:
                    return getShortAt(AUTHORITY_COUNT_LOCATION);
                case SectionType::ADDITIONAL:
                    return getShortAt(ADDITIONAL_COUNT_LOCATION);
            }

            return 0U;
        }

        [[nodiscard]] auto getRecordType(uint16_t position) const -> RecordType {
            return static_cast<RecordType>(getShortAt(position));
        }

        [[nodiscard]] auto getClassType(uint16_t position) const -> ClassType {
            return static_cast<ClassType>(getShortAt(position));
        }

        void setRecordType(uint16_t position, RecordType type) {
            const uint16_t type_uint = htons(static_cast<uint16_t>(type));

            buffer[position] = type_uint & BYTE_MASK;
            buffer[position + 1U] = (type_uint >> BYTE_SHIFT);
        }

        auto getQueryType(RecordType *type) const -> bool {
            uint16_t newPosition = DNS_HEADER_LENGTH;

            if (getSize() < newPosition) {
                return false;
            }

            const uint16_t position = getNamePosition(newPosition);

            if (position == 0U) {
                return false;
            }

            newPosition = position + 4U;

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

            for (uint16_t i = 0U; i < getQueryCount(); i++) {
                const uint16_t position = getNamePosition(newPosition);

                if (position == 0U) {
                    return false;
                }

                newPosition = position + 4U;

                if (getSize() < newPosition) {
                    return false;
                }

                setRecordType(position, newType);
            }

            return true;
        }

        [[nodiscard]] auto getBuffer() const -> uint8_t* {
            return buffer.get();
        }

        [[nodiscard]] auto getCapacity() const -> uint16_t {
            return capacity;
        }

        [[nodiscard]] auto getSize() const -> uint16_t {
            return size;
        }

        void setSize(uint16_t size) {
            this->size = size;
        }

        [[nodiscard]] auto getRecordEnd(uint16_t afterName) const -> uint16_t {
            if (afterName == 0U) {
                return 0U;
            }

            uint16_t newPosition = afterName + LEN_RR_FIXED;

            if (getSize() < newPosition) {
                return 0U;
            }

            newPosition += getShortAt(newPosition - 2U);

            if (getSize() < newPosition) {
                return 0U;
            }

            return newPosition;
        }

        /**
         * @brief Modifies a DNS query to be a response with the RCODE specified as a parameter (supports extended RCODEs)
         *
         * @param code The response code to be set
         */
        void modifyQueryToBeResponse(ResponseCode code) {
            auto *header = reinterpret_cast<DnsHeader *>(buffer.get());

            header->isResponse = 1U;

            if (static_cast<uint16_t>(code) < FIRST_EXTENDED_RCODE) {
                header->responseCode = static_cast<uint8_t>(code);
            } else {
                auto [start, afterName] = RecordParser(*this).parseNext(DnsMessage::SectionType::ADDITIONAL, DnsMessage::RecordType::OPT);

                if (0U == start) {
                    header->responseCode = static_cast<uint16_t>(ResponseCode::FORMERR);
                } else {
                    auto codeValue = static_cast<uint16_t>(code);
                    auto *extendedRcode = reinterpret_cast<ExtendedRcode*>(&codeValue);

                    header->responseCode = extendedRcode->dnsHeaderPortion;
                    buffer[afterName + 4U] = extendedRcode->optRecordPortion;
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

        auto printName(std::ostream &stream, const std::string &name, uint16_t position, bool isCompact) const -> uint16_t;

        void printNumber(std::ostream &stream, const std::string &name, uint32_t number, uint8_t size, bool isCompact) const;

        void printMessage(std::ostream &stream, bool isCompact = false) const;

        void printQType(std::ostream &stream, const std::string &name, uint16_t position, bool isCompact) const;

        void printQClass(std::ostream &stream, const std::string &name, uint16_t position, bool isCompact) const;

        auto printResourceRecord(std::ostream &stream, uint16_t position, bool isCompact) const -> uint16_t;

        void setQueryCount(uint16_t count) {
            setShortAt(QUERY_COUNT_LOCATION, count);
        }

        void setAnswerCount(uint16_t count) {
            setShortAt(ANSWER_COUNT_LOCATION, count);
        }

        void setAuthorityCount(uint16_t count) {
            setShortAt(AUTHORITY_COUNT_LOCATION, count);
        }

        void setAdditionalCount(uint16_t count) {
            setShortAt(ADDITIONAL_COUNT_LOCATION, count);
        }

        /**
         * @brief Adjusts the UDP payload size to the minimum of the current message and the configured value (but at least MAX_NON_EDNS_PACKET bytes)
         *
         * @param configuration The current configuration instance
         * @param rcode A buffer where the response code can be stored if a failure occurs (FORMERR, BADVERS)
         * @return uint16_t The size of the UDP payload size parameter after the adjustment, or zero if an error occurs
         */
        auto updateUdpPayloadSize(const Configuration &configuration, DnsMessage::ResponseCode *rcode) -> uint16_t {
            RecordParser optParser(*this);

            /* TODO: Make EDNS support optional, to increase performance? */
            auto [start, afterName] = optParser.parseNext(DnsMessage::SectionType::ADDITIONAL, DnsMessage::RecordType::OPT);

            /* TODO: Add an OPT record if necessary */
            if (0U == start) {
                return Configuration::MAX_NON_EDNS_PACKET; /* There's no EDNS, so there's no need for a larger buffer */
            }

            auto [start2, afterName2] = optParser.parseNext(DnsMessage::SectionType::ADDITIONAL, DnsMessage::RecordType::OPT);

            /* There are multiple OPT records */
            if (0U != start2) {
                *rcode = DnsMessage::ResponseCode::FORMERR;
                return 0U;
            }

            auto *optRecord = getOptRecord(afterName);

            /* Checking if EDNS version is supported */
            if (optRecord->version > 0U) {
                *rcode = DnsMessage::ResponseCode::BADVERS;
                return 0U;
            }

            uint16_t currentSize = optRecord->getUdpPayloadSize();

            if (currentSize > configuration.getUdpPayloadSize()) {
                setShortAt(afterName + 2U, configuration.getUdpPayloadSize());

                return configuration.getUdpPayloadSize();
            }

            if (currentSize < Configuration::MAX_NON_EDNS_PACKET) {
                setShortAt(afterName + 2U, Configuration::MAX_NON_EDNS_PACKET);

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
        [[nodiscard]] auto validateRrSigTimestamp(uint16_t position) const -> bool {
            auto *header = getRrsigHeader(position);

            /** TODO: What happens after 2038? */
            const time_t timestamp = time(nullptr);

            int result = static_cast<int32_t>(htonl(header->rdata.signatureInception) - static_cast<uint32_t>(timestamp));

            if (result > 0) {
                return false;
            }

            result = static_cast<int32_t>(static_cast<uint32_t>(timestamp) - htonl(header->rdata.signatureExpiration));

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
        [[nodiscard]] auto validateRrSigTypeCovered(uint16_t position, RecordType type) const -> bool {
            auto *header = getRrsigHeader(position);

            return htons(header->rdata.typeCovered) == static_cast<uint16_t>(type);
        }

        [[nodiscard]] auto validateRrSigSignature(RecordType recordType, uint16_t rrsigAfterName, const DnsMessage &dnsKeyMessage) const -> SignatureValidationResult;

        [[nodiscard]] auto getOptRecord(uint16_t position) const -> OptRecord* {
            return reinterpret_cast<OptRecord *>(&buffer[position]);
        }

        [[nodiscard]] auto getRrsigHeader(uint16_t position) const -> RrSigHeader* {
            return reinterpret_cast<RrSigHeader *>(&buffer[position]);
        }

        [[nodiscard]] auto getDnsKeyHeader(uint16_t position) const -> DnsKeyHeader* {
            return reinterpret_cast<DnsKeyHeader *>(&buffer[position]);
        }

        [[nodiscard]] auto getDsHeader(uint16_t position) const -> DsHeader* {
            return reinterpret_cast<DsHeader *>(&buffer[position]);
        }

        [[nodiscard]] auto getRrHeader(uint16_t position) const -> RrHeader* {
            return reinterpret_cast<RrHeader *>(&buffer[position]);
        }

        /**
         * @brief Calculates the DNSKEY key tag according to RFC 4034
         *
         * @param position The position where the DNSKEY RDATA can be found
         * @return uint16_t The calculated key tag
         */
        [[nodiscard]] auto calculateKeyTag(uint16_t position) const -> uint16_t {
            auto *start = &buffer[position];
            auto *header = getRrHeader(position);

            /* Taken from Appendix B of RFC 4034 */

            uint64_t accumulator = 0U;
            auto length = header->getLength();

            for (uint16_t i = 0U; i < length; ++i) {
                accumulator += (i % 2U == 1U) ? start[i + LEN_RR_FIXED] : start[i + LEN_RR_FIXED] << BYTE_SHIFT;
            }

            accumulator += (accumulator >> TWO_BYTE_SHIFT) & LONG_BYTE_MASK;

            return accumulator & LONG_BYTE_MASK;
        }
};

#endif // DNS64SEC_DNS_MESSAGE_H