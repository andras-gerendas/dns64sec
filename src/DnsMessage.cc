/**
 * @file DnsMessage.cc
 * @author Andras Attila Gerendas
 * @brief Class representing a DNS message
 * @version 0.1
 * @date 2022-06-21
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "DnsMessage.h"

#include "OpensslDeleter.h"

#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <syslog.h>

constexpr auto ipv4_mask(uint8_t size) -> uint32_t {
    return (static_cast<uint32_t>(-1)) << (32 - size);
}

/* Non-global IPv4 (RFC 5735), subnet mask */
constexpr uint32_t nonGlobalRanges[15][2] = {
    {0xe0000000, ipv4_mask(4)}, /* 224.0.0.0/4 */
    {0xf0000000, ipv4_mask(4)}, /* 240.0.0.0/4 */
    {0x00000000, ipv4_mask(8)}, /* 0.0.0.0/8 */
    {0x0a000000, ipv4_mask(8)}, /* 10.0.0.0/8 */
    {0x7f000000, ipv4_mask(8)}, /* 127.0.0.0/8 */
    {0xac100000, ipv4_mask(12)}, /* 172.16.0.0/12 */
    {0xc6120000, ipv4_mask(15)}, /* 198.18.0.0/15 */
    {0xc0a80000, ipv4_mask(16)}, /* 192.168.0.0/16 */
    {0xa9fe0000, ipv4_mask(16)}, /* 169.254.0.0/16 */
    {0xc0000000, ipv4_mask(24)}, /* 192.0.0.0/24 */
    {0xc0000200, ipv4_mask(24)}, /* 192.0.2.0/24 */
    {0xc0586300, ipv4_mask(24)}, /* 192.88.99.0/24 */
    {0xc6336400, ipv4_mask(24)}, /* 198.51.100.0/24 */
    {0xcb007100, ipv4_mask(24)}, /* 203.0.113.0/24 */
    {0xffffffff, ipv4_mask(32)}, /* 255.255.255.255/32 */
};

auto DnsMessage::isNonGlobalAddress(uint32_t addr) -> bool {
    const uint32_t address = htonl(addr);

    for (const auto &range : nonGlobalRanges) {
        if ((range[1] & address) == range[0]) {
            syslog(LOG_INFO, "Well-known prefix limits synthesis to global addresses");
            return true;
        }
    }

    return false;
}

void DnsMessage::addQuestion(const std::string &name, RecordType recordType, ClassType classType) {
    generateName(name);
    addShort(static_cast<uint16_t>(recordType));
    addShort(static_cast<uint16_t>(classType));
    setQueryCount(getQueryCount() + 1U);
}

auto DnsMessage::addA(const std::string &ipv4, uint32_t ttl, const std::string &name, ClassType classType) -> bool {
    if (name == "inherit") {
        const uint16_t questionSize = getFirstQuestionSize();

        if (questionSize == 0U) {
            return false;
        }

        memcpy(&buffer[size], &buffer[DNS_HEADER_LENGTH], questionSize);
        size += questionSize;
    } else {
        generateName(name);
        addShort(static_cast<uint16_t>(RecordType::A));
        addShort(static_cast<uint16_t>(classType));
    }

    addInteger(ttl);
    addShort(4U);

    struct in_addr addr;

    const int result = inet_pton(AF_INET, ipv4.c_str(), &addr);

    if (result <= 0) {
        return false;
    }

    /** inet_pton returns the address in network byte order */
    addr.s_addr = ntohl(addr.s_addr);

    addInteger(addr.s_addr);

    setAnswerCount(getAnswerCount() + 1U);

    return true;
}

auto DnsMessage::addAAAA(const std::string &ipv6, uint32_t ttl, const std::string &name, ClassType classType) -> bool {
    if (name == "inherit") {
        const uint16_t questionSize = getFirstQuestionSize();

        if (questionSize == 0) {
            return false;
        }

        memcpy(&buffer[size], &buffer[DNS_HEADER_LENGTH], questionSize);
        size += questionSize;
    } else {
        generateName(name);
        addShort(static_cast<uint16_t>(RecordType::AAAA));
        addShort(static_cast<uint16_t>(classType));
    }

    addInteger(ttl);
    addShort(16U);

    struct in6_addr addr;

    const int result = inet_pton(AF_INET6, ipv6.c_str(), &addr);

    if (result <= 0) {
        return false;
    }

    addInteger(addr.__in6_u.__u6_addr32[0]);
    addInteger(addr.__in6_u.__u6_addr32[1]);
    addInteger(addr.__in6_u.__u6_addr32[2]);
    addInteger(addr.__in6_u.__u6_addr32[3]);

    setAnswerCount(getAnswerCount() + 1U);

    return true;
}

void DnsMessage::addOPT(uint16_t udpPayloadSize, ResponseCode responseCode, uint8_t version, bool dnssecOK) {
    generateName("");
    addShort(static_cast<uint16_t>(RecordType::OPT));
    addShort(udpPayloadSize);
    
    auto codeValue = static_cast<uint16_t>(responseCode);
    auto *extendedRcode = reinterpret_cast<ExtendedRcode*>(&codeValue);

    addByte(extendedRcode->optRecordPortion);
    addByte(version);
    addByte(dnssecOK ? 128U : 0U);
    addByte(0);
    addShort(0);

    setAdditionalCount(getAdditionalCount() + 1U);
}

auto DnsMessage::compareLabelListsBinary(uint16_t firstStart, uint16_t secondStart) const -> int {
    uint8_t length = 0;
    uint16_t firstLabelLocation = firstStart;
    uint16_t secondLabelLocation = secondStart;

    while(length < 255) {
        firstLabelLocation = followPointer(firstLabelLocation);
        secondLabelLocation = followPointer(secondLabelLocation);

        const uint8_t firstLabelLength = getBuffer()[firstLabelLocation];
        const uint8_t secondLabelLength = getBuffer()[secondLabelLocation];

        if (firstLabelLength < secondLabelLength) {
            return -1;
        }

        if (secondLabelLength < firstLabelLength) {
            return 1;
        }

        /** They are equal */
        if (firstLabelLength == 0) {
            return 0;
        }

        for (uint8_t i = 0; i < firstLabelLength; i++) {
            const uint8_t firstByte = std::tolower(getBuffer()[firstLabelLocation + i + 1U]);
            const uint8_t secondByte = std::tolower(getBuffer()[secondLabelLocation + i + 1U]);

            if (firstByte < secondByte) {
                return -1;
            }

            if (secondByte < firstByte) {
                return 1;
            }
        }

        firstLabelLocation += firstLabelLength + 1U;
        secondLabelLocation += firstLabelLength + 1U;
        length += firstLabelLength + 1U;
    }

    /** TODO: Shouldn't this be an error case? */
    return 0;
}

auto DnsMessage::compareLabelListsName(uint16_t firstStart, uint16_t secondStart) const -> int {
    uint16_t firstLabelLocation = 34464U;
    uint16_t secondLabelLocation = 34464U;

    while (true) {
        /** TODO: It is enough to check if the pointers are equal if it's only pointers */
        const uint16_t firstPreviousLabel = getPreviousLabel(firstStart, firstLabelLocation);
        const uint16_t secondPreviousLabel = getPreviousLabel(secondStart, secondLabelLocation);

        const uint8_t firstLabelLength = getBuffer()[firstPreviousLabel];
        const uint8_t secondLabelLength = getBuffer()[secondPreviousLabel];

        const uint8_t longer = firstLabelLength > secondLabelLength ? firstLabelLength : secondLabelLength;

        for (uint8_t i = 0U; i < longer; i++) {
            if (firstLabelLength < i) {
                return -1;
            }

            if (secondLabelLength < i) {
                return 1;
            }

            /** Offsetting the length field */
            const uint8_t firstByte = std::tolower(getBuffer()[firstPreviousLabel + i + 1U]);
            const uint8_t secondByte = std::tolower(getBuffer()[secondPreviousLabel + i + 1U]);

            if (firstByte < secondByte) {
                return -1;
            }

            if (secondByte < firstByte) {
                return 1;
            }
        }

        /** Getting here the second time means the label lists are equal */
        /** TODO: This could be more optimal as it currently checks twice if equal */
        if (firstPreviousLabel == firstLabelLocation && secondPreviousLabel == secondLabelLocation) {
            return 0;
        }

        firstLabelLocation = firstPreviousLabel;
        secondLabelLocation = secondPreviousLabel;
    }
}

void DnsMessage::compressNames() const {
    const uint16_t newPosition = DnsMessage::DNS_HEADER_LENGTH;

    for (uint16_t i = 0U; i < getQueryCount(); i++) {
        const uint16_t position = getNamePosition(newPosition);

        if (position == 0U) {
            return;
        }
    }    
}

void DnsMessage::copyBuffer(DnsMessage *target) const {
    memcpy(target->getBuffer(), getBuffer(), getSize());
    target->setSize(getSize());
}

auto DnsMessage::copyLabelListAsParent(DnsMessage *target) const -> bool {
    const uint16_t nextLabelPosition = getNextLabel(DnsMessage::DNS_HEADER_LENGTH);

    if (nextLabelPosition == 0U) {
        return false;
    }

    const uint16_t labelEndPosition = getNamePosition(DnsMessage::DNS_HEADER_LENGTH);

    if (labelEndPosition == 0U) {
        return false;
    }

    uint16_t position = DnsMessage::DNS_HEADER_LENGTH;

    memcpy(target->getBuffer(), getBuffer(), DnsMessage::DNS_HEADER_LENGTH);

    memcpy(&target->getBuffer()[DnsMessage::DNS_HEADER_LENGTH], &getBuffer()[nextLabelPosition], labelEndPosition - nextLabelPosition);

    position += (labelEndPosition - nextLabelPosition);

    memcpy(&target->getBuffer()[position], &getBuffer()[labelEndPosition], getSize() - labelEndPosition);

    position += getSize() - labelEndPosition;

    target->setSize(position);

    return true;
}

void DnsMessage::generateName(const std::string &name) {
    if (name.empty()) {
        buffer[size] = 0U;
        size++;
        return;
    }

    std::string manip = name;

    /* Convert to canonical format */
    if (manip[manip.length() - 1U] != '.') {
        manip += '.';
    }

    ssize_t dotPosition = size;
    uint8_t nameLength = 0U;

    for (auto i = 0U; i < manip.length(); i++) {
        if (manip[i] == '.') {
            buffer[dotPosition] = nameLength;
            dotPosition = size + i + 1U;
            nameLength = 0U;
        } else {
            buffer[size + i + 1U] = manip[i];
            nameLength++;
        }
    }

    if (manip.length() > 1U) {
        buffer[dotPosition] = 0U;
        size += manip.length() + 1U;
    } else {
        size++;
    }
}

auto DnsMessage::generateSignature(uint8_t *signatureBuffer, uint16_t rrsigAfterName, RecordType queryType) const -> size_t {
    auto *rrsigHeader = getRrsigHeader(rrsigAfterName);

    size_t bufferPosition = 0U;

    const uint16_t signerNameEnd = getNamePosition(rrsigAfterName + DnsMessage::LEN_RRSIG_FIXED);

    const uint16_t signerNameLength = signerNameEnd - rrsigAfterName - DnsMessage::LEN_RRSIG_FIXED;

    /* RRSIG RDATA - Signature */
    memcpy(signatureBuffer, &rrsigHeader->rdata.typeCovered, signerNameLength + DnsMessage::LEN_RRSIG_RDATA_FIXED);

    bufferPosition += signerNameLength + DnsMessage::LEN_RRSIG_RDATA_FIXED;
    
    std::vector<std::pair<uint16_t, uint16_t>> records;

    DnsMessage::RecordParser answerParser(*this);

    while(true) {
        auto [recordStart, recordAfterName] = answerParser.parseNext(DnsMessage::SectionType::ANSWER, queryType);

        if (recordAfterName == 0U) {
            break;
        }

        records.push_back(std::pair(recordStart, recordAfterName));
    }

    const uint16_t typeCovered = rrsigHeader->rdata.getTypeCovered();

    std::sort(records.begin(), records.end(), [this, typeCovered](auto first, auto second) {
        int nameComparisonResult = compareLabelListsName(std::get<0>(first), std::get<0>(second));

        if (nameComparisonResult < 0) {
            return true;
        }

        if (nameComparisonResult > 0) {
            return false;
        }
        
        auto *firstRecordHeader = getRrHeader(std::get<1>(first));
        auto *secondRecordHeader = getRrHeader(std::get<1>(second));

        /* TODO: RFC 4034 6.3. requires the records to be examined for DNS names */
        if (typeCovered == static_cast<uint16_t>(RecordType::NS)) {
            nameComparisonResult = compareLabelListsBinary(std::get<1>(first) + DnsMessage::LEN_RR_FIXED, std::get<1>(second) + DnsMessage::LEN_RR_FIXED);

            if (nameComparisonResult < 0) {
                return true;
            }

            if (nameComparisonResult > 0) {
                return false;
            }
        } else {
            const uint16_t longer = firstRecordHeader->rdlength > secondRecordHeader->rdlength ? firstRecordHeader->rdlength : secondRecordHeader->rdlength;

            for (uint16_t i = 0U; i < longer; i++) {
                if (firstRecordHeader->rdlength < i) {
                    return true;
                }

                if (secondRecordHeader->rdlength < i) {
                    return false;
                }

                const uint8_t firstByte = getBuffer()[std::get<1>(first) + DnsMessage::LEN_RR_FIXED + i];
                const uint8_t secondByte = getBuffer()[std::get<1>(second) + DnsMessage::LEN_RR_FIXED + i];

                if (firstByte < secondByte) {
                    return true;
                }
                
                if (firstByte > secondByte) {
                    return false;
                }
            }
        }

        /** TODO: RFC 4034 6.3. mandates equality to be an error case */
        return true;
    });

    for (auto &record : records) {
        bufferPosition = expandName(signatureBuffer, bufferPosition, std::get<0>(record));

        auto *rrHeader = getRrHeader(std::get<1>(record));

        /* RR TYPE, CLASS */
        memcpy(signatureBuffer + bufferPosition, &getBuffer()[std::get<1>(record)], 4U);

        bufferPosition += 4U;

        /* RRSIG TTL --> RR TTL */
        memcpy(signatureBuffer + bufferPosition, &rrsigHeader->rdata.originalTtl, 4U);

        bufferPosition += 4U;

        const uint16_t rrHeaderLength = rrHeader->getLength();

        /** Needed to update if expansion happens */
        const uint16_t rdLengthPosition = bufferPosition;

        /* RR RDLENGTH */
        memcpy(signatureBuffer + bufferPosition, (uint8_t *)&rrHeader->rdlength, 2U);

        bufferPosition += 2U;

        const uint16_t startingPosition = bufferPosition;

        /* RR RDATA */
        if (typeCovered == static_cast<uint16_t>(RecordType::NS)) {
            bufferPosition = expandName(signatureBuffer, bufferPosition, std::get<1>(record) + DnsMessage::LEN_RR_FIXED);
        } else if (typeCovered == static_cast<uint16_t>(RecordType::SOA)) {
            /** MNAME */
            bufferPosition = expandName(signatureBuffer, bufferPosition, std::get<1>(record) + DnsMessage::LEN_RR_FIXED);
            uint16_t nameEndPosition = getNamePosition(std::get<1>(record) + DnsMessage::LEN_RR_FIXED);
            /** RNAME */
            bufferPosition = expandName(signatureBuffer, bufferPosition, nameEndPosition);
            nameEndPosition = getNamePosition(nameEndPosition);
            /** Rest of the values */
            memcpy(signatureBuffer + bufferPosition, &getBuffer()[nameEndPosition], DnsMessage::LEN_SOA_RDATA_FIXED);

            bufferPosition += DnsMessage::LEN_SOA_RDATA_FIXED;
        } else {
            memcpy(signatureBuffer + bufferPosition, &getBuffer()[std::get<1>(record) + DnsMessage::LEN_RR_FIXED], rrHeaderLength);

            bufferPosition += rrHeaderLength;
        }

        uint16_t rrLength = htons(bufferPosition - startingPosition);

        memcpy(signatureBuffer + rdLengthPosition, (uint8_t *)&rrLength, 2);
    }

    return bufferPosition;
};

auto DnsMessage::expandName(uint8_t *signatureBuffer, uint16_t bufferPosition, uint16_t position) const -> size_t {
    uint16_t length = 0U;
    uint16_t currentPos = position;
    uint16_t currentLength = 0U;

    while(length < 255U) {
        /** TODO: Shouldn't follow pointers until eternity */
        currentPos = followPointer(currentPos);

        if (currentPos == 0U) {
            return 0U;
        }

        signatureBuffer[bufferPosition] = buffer[currentPos];
        bufferPosition++;

        if (buffer[currentPos] == 0U) {
            length += 1U;
            break;
        }

        if (currentLength > 0U) {
            currentLength--;
        } else {
            currentLength = buffer[currentPos];
        }

        length++;
        currentPos++;
    }

    return bufferPosition;
}

auto DnsMessage::generateSynthetisedMessage(const Configuration &configuration, DnsMessage *message) const -> bool {
    auto *forged_buffer = message->getBuffer();
    const uint16_t buffer_capacity = message->getCapacity();

    uint16_t newPosition = DNS_HEADER_LENGTH;

    if (getSize() < newPosition) {
        return false;
    }

    /* Copying in the header */
    memcpy(forged_buffer, buffer.get(), newPosition);

    for (uint16_t i = 0U; i < getQueryCount(); i++) {
        const uint16_t position = getNamePosition(newPosition);

        if (position == 0U) {
            return false;
        }

        const uint16_t offset = position + 4U;

        if (getSize() < offset) {
            return false;
        }

        /* Copying in the query */
        memcpy(forged_buffer + newPosition, buffer.get() + newPosition, offset - newPosition);
        newPosition = offset;

        if (message->getRecordType(offset - 4U) == DnsMessage::RecordType::A && message->getClassType(offset - 2U) == DnsMessage::ClassType::IN) {
            message->setRecordType(offset - 4U, DnsMessage::RecordType::AAAA);
        }
    }

    uint16_t oldPosition = newPosition;

    for (uint16_t i = 0U; i < getAnswerCount(); i++) {
        const uint16_t position = getNamePosition(oldPosition);

        if (position == 0U) {
            return false;
        }

        const uint16_t offset = position + LEN_RR_FIXED;

        if (getSize() < offset) {
            return false;
        }

        /* Copying in the beginning of the answer (except the address) */
        memcpy(forged_buffer + newPosition, buffer.get() + oldPosition, offset - oldPosition);

        const uint16_t difference = newPosition - oldPosition;

        newPosition = offset + difference;
        oldPosition = offset;

        if (message->getRecordType(offset + difference - 10U) == DnsMessage::RecordType::A && message->getClassType(offset + difference - 8U) == DnsMessage::ClassType::IN) {
            message->setRecordType(offset + difference - 10U, DnsMessage::RecordType::AAAA);

            if (getSize() < oldPosition + LEN_IPV4_ADDR || buffer_capacity < newPosition + LEN_IPV6_ADDR) {
                return false;
            }

            /* Adding the IPv4 address with the DNS64 prefix */

            const uint8_t prefixLength = configuration.getPrefixLength();

            uint8_t *dest = forged_buffer + newPosition;
            uint8_t *src = buffer.get() + oldPosition;

            if (configuration.isWellKnown()) {
                if (isNonGlobalAddress(*reinterpret_cast<uint32_t *>(src))) {
                    return false;
                }
            }

            /* Updating the data length 4 --> 16 */
            forged_buffer[offset + difference - 1] = LEN_IPV6_ADDR;

            /* 96 fills up the whole buffer */
            if (PREFIX_96_BIT_PREFIX != prefixLength) {
                memset(dest, 0, LEN_IPV6_ADDR);
            }

            memcpy(dest, configuration.getPrefix().__in6_u.__u6_addr8, prefixLength / 8U);

            switch(prefixLength) {
                case PREFIX_32_BIT:
                    memcpy(dest + LEN_IPV4_ADDR, src, LEN_IPV4_ADDR);
                    break;

                case PREFIX_40_BIT:
                    memcpy(dest + PREFIX_40_BIT_PREFIX, src, IPV4_ADDR_THREE_BYTE);
                    memcpy(dest + PREFIX_40_BIT_SUFFIX, src + IPV4_ADDR_THREE_BYTE, IPV4_ADDR_ONE_BYTE);
                    break;

                case PREFIX_48_BIT:
                    memcpy(dest + PREFIX_48_BIT_PREFIX, src, IPV4_ADDR_HALF);
                    memcpy(dest + PREFIX_48_BIT_SUFFIX, src + IPV4_ADDR_HALF, IPV4_ADDR_HALF);
                    break;

                case PREFIX_56_BIT:
                    memcpy(dest + PREFIX_56_BIT_PREFIX, src, IPV4_ADDR_ONE_BYTE);
                    memcpy(dest + PREFIX_56_BIT_SUFFIX, src + IPV4_ADDR_ONE_BYTE, IPV4_ADDR_THREE_BYTE);
                    break;

                case PREFIX_64_BIT:
                    memcpy(dest + PREFIX_64_BIT_PREFIX, src, LEN_IPV4_ADDR);
                    break;

                case PREFIX_96_BIT:
                    memcpy(dest + PREFIX_96_BIT_PREFIX, src, LEN_IPV4_ADDR);
                    break;

                default:
                    break;
            }

            newPosition += LEN_IPV6_ADDR;
            oldPosition += LEN_IPV4_ADDR;
        } else {
            newPosition += forged_buffer[offset + difference - 1U];
            oldPosition += forged_buffer[offset + difference - 1U];

            if (getSize() < oldPosition || buffer_capacity < newPosition) {
                return false;
            }
        }
    }

    message->size = newPosition;

    return true;
}

auto DnsMessage::printName(std::ostream &stream, const std::string &name, uint16_t position, bool isCompact) const -> uint16_t {
    uint16_t length = 0U;
    uint16_t currentPos = position;
    uint16_t currentLength = 0U;

    if (!isCompact) {
        stream << "|";
    } else {
        stream << name << "=";
    }

    while(length < 255U) {
        currentPos = followPointer(currentPos);

        if (currentPos == 0U) {
            return 0U;
        }

        if (buffer[currentPos] == 0U) {
            if (!isCompact) {
                printNumber(stream, "", 0U, 1U, isCompact);
            }

            length += 1U;
            break;
        }

        if (currentLength > 0U) {
            if (!isCompact) {
                stream << std::setw(4) << static_cast<char>(buffer[currentPos]) << "|";
            } else {
                stream << static_cast<char>(buffer[currentPos]);
            }
            currentLength--;
        } else {
            currentLength = buffer[currentPos];
            if (!isCompact) {
                printNumber(stream, "", currentLength, 1U, isCompact);
            } else if (length > 0) {
                stream << ".";
            }
        }

        length++;
        currentPos++;

        if (length % 16U == 0U && !isCompact) {
            stream << "\n|";
        }
    }

    if (length % 16U != 0U && !isCompact) {
        const uint8_t remaining = 79U - (length % 16U * 5U);

        if (remaining > 4U + name.size()) {
            stream << std::setw(79U - (length % 16U * 5U) - name.size() - 1U) << "(" << name << ")" << "|";
        } else {
            stream << std::setw(79U - (length % 16U * 5U)) << "" << "|";
        }
    }

    return length;
}

void DnsMessage::printNumber(std::ostream &stream, const std::string &name, uint32_t number, uint8_t size, bool isCompact) const {
    const bool isWholeLine = size == 16U;

    size *= 5U;

    if (isWholeLine) {
        if (!isCompact) {
            stream << "|";
        }
    }

    if (name.empty()) {
        if (!isCompact) {
            size -= 1U;
            stream << std::setw(size) << number << "|";
        } else {
            stream << number << ",";
        }
    } else {
        if (!isCompact) {
            size -= (name.length() + 2U);
            stream << name << "=" << std::setw(size) << number << "|";
        } else {
            if (number != 0) {
                stream << name << "=" << number << ",";
            }
        }
    }

    if (isWholeLine) {
        if (!isCompact) {
            stream << "\n";
        }
    }
}

void DnsMessage::printQType(std::ostream &stream, const std::string &name, uint16_t position, bool isCompact) const {
    const auto value = static_cast<RecordType>(getShortAt(position));

    std::string stringValue;

    switch (value) {
        case RecordType::A:
            stringValue = "A";
            break;
        case RecordType::NS:
            stringValue = "NS";
            break;
        case RecordType::CNAME:
            stringValue = "CNAME";
            break;
        case RecordType::SOA:
            stringValue = "SOA";
            break;
        case RecordType::PTR:
            stringValue = "PTR";
            break;
        case RecordType::MX:
            stringValue = "MX";
            break;
        case RecordType::TXT:
            stringValue = "TXT";
            break;
        case RecordType::RP:
            stringValue = "RP";
            break;
        case RecordType::AFSDB:
            stringValue = "AFSDB";
            break;
        case RecordType::SIG:
            stringValue = "SIG";
            break;
        case RecordType::KEY:
            stringValue = "KEY";
            break;
        case RecordType::AAAA:
            stringValue = "AAAA";
            break;
        case RecordType::LOC:
            stringValue = "LOC";
            break;
        case RecordType::SRV:
            stringValue = "SRV";
            break;
        case RecordType::NAPTR:
            stringValue = "NAPTR";
            break;
        case RecordType::KX:
            stringValue = "KX";
            break;
        case RecordType::CERT:
            stringValue = "CERT";
            break;
        case RecordType::DNAME:
            stringValue = "DNAME";
            break;
        case RecordType::OPT:
            stringValue = "OPT";
            break;
        case RecordType::APL:
            stringValue = "APL";
            break;
        case RecordType::DS:
            stringValue = "DS";
            break;
        case RecordType::SSHFP:
            stringValue = "SSHFP";
            break;
        case RecordType::IPSECKEY:
            stringValue = "IPSECKEY";
            break;
        case RecordType::RRSIG:
            stringValue = "RRSIG";
            break;
        case RecordType::NSEC:
            stringValue = "NSEC";
            break;
        case RecordType::DNSKEY:
            stringValue = "DNSKEY";
            break;
        case RecordType::DHCID:
            stringValue = "DHCID";
            break;
        case RecordType::NSEC3:
            stringValue = "NSEC3";
            break;
        case RecordType::NSEC3PARAM:
            stringValue = "NSEC3PARAM";
            break;
        case RecordType::HIP:
            stringValue = "HIP";
            break;
        case RecordType::SPF:
            stringValue = "SPF";
            break;
        case RecordType::TKEY:
            stringValue = "TKEY";
            break;
        case RecordType::TSIG:
            stringValue = "TSIG";
            break;
        case RecordType::TA:
            stringValue = "TA";
            break;
        case RecordType::DLV:
            stringValue = "DLV";
            break;
        default:
            stringValue = "[UNKNOWN]";
            break;
    }

    if (isCompact) {
        stream << name << "=" << stringValue << ",";
    } else {
        stream << "|" << name << "=" << std::setw(80U - name.size() - 2U) << stringValue << "|\n";
    }
}

void DnsMessage::printQClass(std::ostream &stream, const std::string &name, uint16_t position, bool isCompact) const {
    const auto value = static_cast<ClassType>(getShortAt(position));

    std::string stringValue;

    switch (value) {
        case ClassType::IN:
            stringValue = "IN";
            break;
        default:
            stringValue = "[UNKNOWN]";
            break;
    }

    if (isCompact) {
        stream << name << "=" << stringValue << ",";
    } else {
        stream << "|" << name << "=" << std::setw(80U - name.size() - 2U) << stringValue << "|\n";
    }
}

auto DnsMessage::printResourceRecord(std::ostream &stream, uint16_t position, bool isCompact) const -> uint16_t {
    stream << "\n";

    position += printName(stream, "NAME", position, isCompact);

    if (!isCompact) {
        stream << "\n";
    } else {
        stream << ",";
    }

    const uint16_t recordTypePosition = position;
    printQType(stream, "TYPE", position, isCompact);
    position += 2U;
    printQClass(stream, "CLASS", position, isCompact);
    position += 2U;

    if (isCompact) {
        if (getIntegerAt(position) > 0U) {
            stream << "TTL=" << getIntegerAt(position) << ",";
        }
    } else {
        stream << "|TTL=" << std::setw(75) << "" << "|\n";
        printNumber(stream, "", getIntegerAt(position), 16U, isCompact);
    }

    position += 4U;
    printNumber(stream, "RDLENGTH", getShortAt(position), 16U, isCompact);
    position += 2U;

    if (getRecordType(recordTypePosition) == RecordType::A) {
        if (isCompact) {
            std::array<char, INET_ADDRSTRLEN> address;
            uint32_t hostAddress = htonl(getIntegerAt(position));
            inet_ntop(AF_INET, &hostAddress, address.data(), INET_ADDRSTRLEN);
            stream << "RDATA=" << address.data() << "\n";
        } else {
            for (uint8_t i = 0U; i < 4U; i++) {
                if (i == 2U) {
                    stream << "\n";
                }

                if (i % 2U == 0U) {
                    stream << "|";
                }

                if (i == 0U) {
                    printNumber(stream, "RDATA", buffer[position + i], 8U, isCompact);
                } else {
                    printNumber(stream, "", buffer[position + i], 8U, isCompact);
                }
            }

            stream << "\n";
        }

        position += 4U;
    } else if (getRecordType(recordTypePosition) == RecordType::DNSKEY) {
        printNumber(stream, "FLAGS", buffer[position], 16U, isCompact);
        position += 2U;

        if (!isCompact) {
            stream << "|";
        }

        printNumber(stream, "PROTO", buffer[position], 8U, isCompact);
        position++;
        printNumber(stream, "ALGO", buffer[position], 8U, isCompact);
        position++;

        if (!isCompact) {
            stream << "\n";
        }
    } else if (getRecordType(recordTypePosition) == RecordType::NS) {
        position += printName(stream, "NSDNAME", position, isCompact);
    } else if (getRecordType(recordTypePosition) == RecordType::RRSIG) {
        printQType(stream, "Type Covered", position, isCompact);
        position += 2U;

        if (!isCompact) {
            stream << "|";
        }

        printNumber(stream, "ALGO", buffer[position], 8U, isCompact);
        position++;
        printNumber(stream, "LABEL", buffer[position], 8U, isCompact);
        position++;

        if (!isCompact) {
            stream << "\n";
        }

        printNumber(stream, "Original TTL", getIntegerAt(position), 16U, isCompact);
        position += 4U;
        printNumber(stream, "Signature Expiration", getIntegerAt(position), 16U, isCompact);
        position += 4U;
        printNumber(stream, "Signature Inception", getIntegerAt(position), 16U, isCompact);
        position += 4U;
        printNumber(stream, "Key Tag", getShortAt(position), 16U, isCompact);
        position += 2U;
        position += printName(stream, "Signer's Name", position, isCompact);

        if (!isCompact) {
            stream << "\n";
        } else {
            stream << ",";
        }
    }

    return position;
}

void DnsMessage::printMessage(std::ostream &stream, bool isCompact) const {
    if (!isCompact) {
        stream << "|";

        for (uint8_t i = 0U; i < 16U; i++) {
            stream << std::setw(4) << i << "|";
        }

        stream << "\n";
    }

    auto *header = reinterpret_cast<DnsHeader *>(buffer.get());

    printNumber(stream, "ID", header->identifier, 16U, isCompact);

    if (!isCompact) {
        stream << "|";
    }

    printNumber(stream, "QR", header->isResponse, 1U, isCompact);
    printNumber(stream, "OpCode", header->opcode, 4U, isCompact);
    printNumber(stream, "AA", header->authoritative, 1U, isCompact);
    printNumber(stream, "TC", header->truncated, 1U, isCompact);
    printNumber(stream, "RD", header->recursionDesired, 1U, isCompact);
    printNumber(stream, "RA", header->recursionAvailable, 1U, isCompact);
    printNumber(stream, "Z", header->z, 1U, isCompact);
    printNumber(stream, "AD", header->authenticatedData, 1U, isCompact);
    printNumber(stream, "CD", header->checkingDisabled, 1U, isCompact);
    printNumber(stream, "RCODE", header->responseCode, 4U, isCompact);

    if (!isCompact) {
        stream << "\n";
    }

    printNumber(stream, "QDCOUNT", getQueryCount(), 16U, isCompact);
    printNumber(stream, "ANCOUNT", getAnswerCount(), 16U, isCompact);
    printNumber(stream, "NSCOUNT", getAuthorityCount(), 16U, isCompact);
    printNumber(stream, "ARCOUNT", getAdditionalCount(), 16U, isCompact);

    uint16_t position = DNS_HEADER_LENGTH;

    if (getQueryCount() > 0U) {
        for (uint16_t i = 0U; i < getQueryCount(); i++) {
            if (isCompact) {
                stream << "\n";
            }

            position += printName(stream, "QNAME", position, isCompact);

            if (isCompact) {
                stream << ",";
            } else {
                stream << "\n";
            }

            printQType(stream, "QTYPE", position, isCompact);
            position += 2U;
            printQClass(stream, "QCLASS", position, isCompact);
            position += 2U;
        }
    } else if (!isCompact) {
        stream << "|" << std::setw(79) << "[No queries]" << "|\n";
    }

    if (getAnswerCount() > 0U) {
        for (uint16_t i = 0U; i < getAnswerCount(); i++) {
            position = printResourceRecord(stream, position, isCompact);
        }
    } else if (!isCompact) {
        stream << "|" << std::setw(79) << "[No answers]" << "|\n";
    }

    if (getAdditionalCount() > 0U) {
        for (uint16_t i = 0U; i < getAdditionalCount(); i++) {
            position = printResourceRecord(stream, position, isCompact);
        }
    } else if (!isCompact) {
        stream << "|" << std::setw(79) << "[No additionals]" << "|\n";
    }
}

auto DnsMessage::validateRrSigSignature(RecordType recordType, uint16_t rrsigAfterName, const DnsMessage &dnsKeyMessage) const -> SignatureValidationResult {
    auto *rrsigHeader = getRrsigHeader(rrsigAfterName);

    RecordParser dnsKeyParser(dnsKeyMessage);

    while (true) {
        auto [dnsKeyStart, dnsKeyAfterName] = dnsKeyParser.parseNext(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::DNSKEY);

        if (0U == dnsKeyAfterName) {
            return SignatureValidationResult::KEY_NOT_FOUND;
        }

        auto *dnsKeyHeader = dnsKeyMessage.getDnsKeyHeader(dnsKeyAfterName);

        /* DNSKEY has to be a zone key to be used for validation */
        if (!dnsKeyHeader->isZoneKey) {
            syslog(LOG_DEBUG, "DNSKEY is not a zone key");
            continue;
        }

        if (dnsKeyHeader->algorithm != rrsigHeader->rdata.algorithm) {
            syslog(LOG_DEBUG, "The algorithms of DNSKEY (%u) and RRSIG (%u) do not match", dnsKeyHeader->algorithm, rrsigHeader->rdata.algorithm);
            continue;
        }

        if (recordType != static_cast<DnsMessage::RecordType>(rrsigHeader->rdata.getTypeCovered())) {
            return SignatureValidationResult::TYPE_COVERED_INVALID;
        }

        /** Currently checking twice to make sure an unnecessary DNSKEY request is not sent */
        if (!validateRrSigTimestamp(rrsigAfterName)) {
            return SignatureValidationResult::TIMESTAMP_INVALID;
        }

        auto keyTag = dnsKeyMessage.calculateKeyTag(dnsKeyAfterName);
        auto rrsigTag = rrsigHeader->rdata.getKeyTag();

        if (keyTag != rrsigTag) {
            syslog(LOG_DEBUG, "The key tags of DNSKEY (%u) and RRSIG (%u) do not match", keyTag, rrsigTag);
            continue;
        }

        syslog(LOG_DEBUG, "DNSKEY and RRSIG match, keytag: %u, algo: %u", keyTag, dnsKeyHeader->algorithm);

        uint8_t* signatureStart = &dnsKeyHeader->algorithm + 1U;

        const char *contextName = nullptr;

        if (dnsKeyHeader->algorithm == static_cast<uint8_t>(KeyType::RSA_SHA256)) {
            contextName = "RSA";
        } else if (dnsKeyHeader->algorithm == static_cast<uint8_t>(KeyType::ECDSA_SHA256)) {
            contextName = "EC";
        }

        const EvpPkeyCtxPtr keyContext(EVP_PKEY_CTX_new_from_name(nullptr, contextName, nullptr));

        if (nullptr == keyContext) {
            syslog(LOG_DEBUG, "Could not allocate EVP key context: %s", ERR_error_string(ERR_get_error(), nullptr));
            continue;
        }

        int result = EVP_PKEY_fromdata_init(keyContext.get());

        if (0 >= result) {
            syslog(LOG_DEBUG, "Could not initialize EVP PKEY: %s", ERR_error_string(ERR_get_error(), nullptr));
            continue;
        }

        EvpPkeyPtr pkey;

        if (dnsKeyHeader->algorithm == static_cast<uint8_t>(KeyType::RSA_SHA256)) {
            const size_t expLength = signatureStart[0U];
            const size_t modulusLength = dnsKeyHeader->header.getLength() - 4U - expLength - 1U;

            OSSL_PARAM params[] = {
                OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, (void *)&signatureStart[1 + expLength], modulusLength),
                OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, (void *)&signatureStart[1], expLength),
                OSSL_PARAM_END
            };

    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            std::reverse(&signatureStart[1U + expLength], &signatureStart[1U + expLength + modulusLength]);
            std::reverse(&signatureStart[1U], &signatureStart[1U + expLength]);
    #endif

            /** When signing DNSKEYs the unreversed key is needed for signature generation */
            EVP_PKEY* raw_pkey = nullptr;
            result = EVP_PKEY_fromdata(keyContext.get(), &raw_pkey, EVP_PKEY_PUBLIC_KEY, params);
            pkey.reset(raw_pkey);

    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            std::reverse(&signatureStart[1U + expLength], &signatureStart[1U + expLength + modulusLength]);
            std::reverse(&signatureStart[1U], &signatureStart[1U + expLength]);
    #endif
        } else if (dnsKeyHeader->algorithm == static_cast<uint8_t>(KeyType::ECDSA_SHA256)) {
            unsigned char octet_string[65U];
            octet_string[0U] = 0x04U;
            memcpy(&octet_string[1U], &signatureStart[0U], 64U);

            OSSL_PARAM params[] = {
                OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (void *)"prime256v1", 0U),
                OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, octet_string, sizeof(octet_string)),
                OSSL_PARAM_END
            };

            EVP_PKEY* raw_pkey = nullptr;
            result = EVP_PKEY_fromdata(keyContext.get(), &raw_pkey, EVP_PKEY_PUBLIC_KEY, params);
            pkey.reset(raw_pkey);
        }

        if (0 >= result) {
            syslog(LOG_DEBUG, "Could not create key structure: %s", ERR_error_string(ERR_get_error(), nullptr));
            continue;
        }

        const EvpPkeyCtxPtr verifyContext(EVP_PKEY_CTX_new(pkey.get(), nullptr));

        if (nullptr == verifyContext) {
            syslog(LOG_DEBUG, "Could not allocate EVP verify context: %s", ERR_error_string(ERR_get_error(), nullptr));
            continue;
        }

        result = EVP_PKEY_verify_init(verifyContext.get());

        if (0 >= result) {
            syslog(LOG_DEBUG, "Could not initialize EVP verify: %s", ERR_error_string(ERR_get_error(), nullptr));
            continue;
        }

        result = EVP_PKEY_CTX_set_signature_md(verifyContext.get(), EVP_sha256());

        if (0 >= result) {
            syslog(LOG_DEBUG, "Could not set EVP signature");
            continue;
        }

        if (dnsKeyHeader->algorithm == static_cast<uint8_t>(KeyType::RSA_SHA256)) {
            result = EVP_PKEY_CTX_set_rsa_padding(verifyContext.get(), RSA_PKCS1_PADDING);

            if (result <= 0) {
                syslog(LOG_DEBUG, "Could not set RSA padding");
                continue;
            }
        }

        /** TODO: This should be put to a central place */
        auto signatureBuffer = std::make_unique<uint8_t[]>(DnsMessage::MAX_LEN_SIG_BUFFER);

        const uint16_t signerNameEnd = getNamePosition(rrsigAfterName + DnsMessage::LEN_RRSIG_FIXED);

        const uint16_t signerNameLength = signerNameEnd - rrsigAfterName - DnsMessage::LEN_RRSIG_FIXED;

        auto bufferPosition = generateSignature(signatureBuffer.get(), rrsigAfterName, recordType);

        std::array<unsigned char, SHA256_DIGEST_LENGTH> hash{};

        EvpMdCtxPtr mdctx(EVP_MD_CTX_create());

        EVP_DigestInit_ex(mdctx.get(), EVP_sha256(), nullptr);
        EVP_DigestUpdate(mdctx.get(), signatureBuffer.get(), bufferPosition);
        EVP_DigestFinal_ex(mdctx.get(), hash.data(), nullptr);

        mdctx.reset();

        OpenSSLBytesPtr der_sig_owner;
        uint8_t *der_sig = nullptr;
        size_t der_len = 0;

        if (dnsKeyHeader->algorithm == static_cast<uint8_t>(KeyType::RSA_SHA256)) {
            der_sig = &getBuffer()[signerNameEnd];
            der_len = rrsigHeader->header.getLength() - signerNameLength - DnsMessage::LEN_RRSIG_RDATA_FIXED;
        } else if (dnsKeyHeader->algorithm == static_cast<uint8_t>(KeyType::ECDSA_SHA256)) {
            const EcdsaSigPtr ec_sig(ECDSA_SIG_new());

            BnPtr param_r(BN_bin2bn(&getBuffer()[signerNameEnd], 32, nullptr));
            BnPtr param_s(BN_bin2bn(&getBuffer()[signerNameEnd + 32U], 32, nullptr));

            result = ECDSA_SIG_set0(ec_sig.get(), param_r.get(), param_s.get());

            if (result == 1) {
                param_r.release();
                param_s.release();
            }

            der_len = i2d_ECDSA_SIG(ec_sig.get(), &der_sig);
            der_sig_owner.reset(der_sig);
        }

        if (1 == EVP_PKEY_verify(verifyContext.get(), der_sig, der_len, hash.data(), SHA256_DIGEST_LENGTH)) {
            return SignatureValidationResult::SUCCESS;
        }

        unsigned long err = 0;

        while ((err = ERR_get_error()) != 0) {
            /* This is not an error condition, checking next key */
            syslog(LOG_DEBUG, "Key validation has failed: %s", ERR_error_string(err, nullptr));
        }
    }

    return SignatureValidationResult::KEY_NOT_FOUND;
}