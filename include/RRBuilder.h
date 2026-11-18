/**
 * @file RRBuilder.h
 * @author Andras Attila Gerendas
 * @brief Builder for a Resource Record
 * @version 0.1
 * @date 2026-10-23
 *
 * @copyright Copyright (c) 2026
 *
 */

#ifndef DNS64SEC_RR_BUILDER_H
#define DNS64SEC_RR_BUILDER_H

#include "DnsMessage.h"

class RRBuilder {
    std::string name;
    DnsMessage::RecordType type;
    DnsMessage::ClassType qclass;
    uint32_t ttl{0};
    uint16_t rdlength{0};

    protected:
        uint16_t setBit(uint16_t currentValue, uint8_t position) {
            return currentValue | (1 << (15 - position));
        }

    public:
        RRBuilder(const std::string &name, DnsMessage::RecordType type, DnsMessage::ClassType qclass) : name(name), type(type), qclass(qclass) {}

        void build(DnsMessage &target) {
            buildHeader(target);

            auto lengthLocation = target.getSize() - 2;

            buildBody(target, lengthLocation);

            target.setShortAt(lengthLocation, target.getSize() - lengthLocation - 2);
        }

        void buildHeader(DnsMessage &target) {
            target.generateName(name);
            target.addShort(static_cast<uint16_t>(type));
            target.addShort(static_cast<uint16_t>(qclass));
            target.addInteger(ttl);
            target.addShort(rdlength);
        }

        virtual void buildBody(DnsMessage &target, uint16_t lengthLocation) = 0;

        RRBuilder& setTtl(uint32_t ttl) {
            this->ttl = ttl;
            return *this;
        }

        RRBuilder& setDataLength(uint16_t rdlength) {
            this->rdlength = rdlength;
            return *this;
        }
};

#endif // DNS64SEC_RR_BUILDER_H