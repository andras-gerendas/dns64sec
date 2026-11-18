/**
 * @file NsBuilder.h
 * @author Andras Attila Gerendas
 * @brief Builder for an NS Resource Record
 * @version 0.1
 * @date 2026-10-25
 *
 * @copyright Copyright (c) 2026
 *
 */

#ifndef DNS64SEC_NS_BUILDER_H
#define DNS64SEC_NS_BUILDER_H

#include "RRBuilder.h"

class NsBuilder : public RRBuilder {
    std::string nameserver;

    public:
        NsBuilder(const std::string &name, DnsMessage::ClassType qclass = DnsMessage::ClassType::IN) : RRBuilder(name, DnsMessage::RecordType::NS, qclass) {}

        virtual void buildBody(DnsMessage &target, uint16_t /*lengthLocation*/) override {
            target.generateName(nameserver);
            target.setAnswerCount(target.getAnswerCount() + 1);
        }

        NsBuilder &setNameserver(const std::string &nameserver) {
            this->nameserver = nameserver;

            return *this;
        }
};

#endif // DNS64SEC_NS_BUILDER_H