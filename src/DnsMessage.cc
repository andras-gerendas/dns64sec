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

#include <cstring>
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
    uint32_t address = htonl(addr);

    for (const auto &range : nonGlobalRanges) {
        if ((range[1] & address) == range[0]) {
            syslog(LOG_INFO, "Well-known prefix limits synthesis to global addresses");
            return true;
        }
    }

    return false;
}

auto DnsMessage::generateSynthetisedMessage(const Configuration &configuration, DnsMessage *message) const -> bool {
    auto *forged_buffer = message->getBuffer();
    uint16_t buffer_size = message->getSize();

    uint16_t newPosition = DNS_HEADER_LENGTH;

    if (getSize() < newPosition) {
        return false;
    }

    /* Copying in the header */
    memcpy(forged_buffer, buffer, newPosition);

    for (uint16_t i = 0; i < getQueryCount(); i++) {
        uint16_t position = getNamePosition(newPosition);

        if (position == 0) {
            return false;
        }

        uint16_t offset = position + 4;

        if (getSize() < offset) {
            return false;
        }

        /* Copying in the query */
        memcpy(forged_buffer + newPosition, buffer + newPosition, offset - newPosition);
        newPosition = offset;

        if (message->getRecordType(offset - 4) == DnsMessage::RecordType::A && message->getClassType(offset - 2) == DnsMessage::ClassType::IN) {
            message->setRecordType(offset - 4, DnsMessage::RecordType::AAAA);
        }
    }

    uint16_t oldPosition = newPosition;

    for (uint16_t i = 0; i < getAnswerCount(); i++) {
        uint16_t position = getNamePosition(oldPosition);

        if (position == 0) {
            return false;
        }

        uint16_t offset = position + LEN_RR_FIXED;

        if (getSize() < offset) {
            return false;
        }

        /* Copying in the beginning of the answer (except the address) */
        memcpy(forged_buffer + newPosition, buffer + oldPosition, offset - oldPosition);

        uint16_t difference = newPosition - oldPosition;

        newPosition = offset + difference;
        oldPosition = offset;

        if (message->getRecordType(offset + difference - 10) == DnsMessage::RecordType::A && message->getClassType(offset + difference - 8) == DnsMessage::ClassType::IN) {
            message->setRecordType(offset + difference - 10, DnsMessage::RecordType::AAAA);

            if (getSize() < oldPosition + 4 || buffer_size < newPosition + 16) {
                return false;
            }

            /* Adding the IPv4 address with the DNS64 prefix */

            uint8_t prefixLength = configuration.getPrefixLength();

            uint8_t *dest = forged_buffer + newPosition;
            uint8_t *src = buffer + oldPosition;

            if (configuration.isWellKnown()) {
                if (isNonGlobalAddress(*reinterpret_cast<uint32_t *>(src))) {
                    return false;
                }
            }

            /* Updating the data length 4 --> 16 */
            forged_buffer[offset + difference - 1] = 16U;

            /* 96 fills up the whole buffer */
            if (96 != prefixLength) {
                memset(dest, 0, 16);
            }

            memcpy(dest, configuration.getPrefix().__in6_u.__u6_addr8, prefixLength / 8);

            switch(prefixLength) {
                case 32:
                    memcpy(dest + 4, src, 4);
                    break;

                case 40:
                    memcpy(dest + 5, src, 3);
                    memcpy(dest + 9, src + 3, 1);
                    break;

                case 48:
                    memcpy(dest + 6, src, 2);
                    memcpy(dest + 9, src + 2, 2);
                    break;

                case 56:
                    memcpy(dest + 7, src, 1);
                    memcpy(dest + 9, src + 1, 3);
                    break;

                case 64:
                    memcpy(dest + 9, src, 4);
                    break;

                case 96:
                    memcpy(dest + 12, src, 4);
                    break;

                default:
                    break;
            }

            newPosition += 16;
            oldPosition += 4;
        } else {
            newPosition += forged_buffer[offset + difference - 1];
            oldPosition += forged_buffer[offset + difference - 1];

            if (getSize() < oldPosition || buffer_size < newPosition) {
                return false;
            }
        }
    }

    message->size = newPosition;

    return true;
}