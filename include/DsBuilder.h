/**
 * @file DsBuilder.h
 * @author Andras Attila Gerendas
 * @brief Builder for a DS Resource Record
 * @version 0.1
 * @date 2026-10-25
 *
 * @copyright Copyright (c) 2026
 *
 */

#ifndef DNS64SEC_DS_BUILDER_H
#define DNS64SEC_DS_BUILDER_H

#include "RRBuilder.h"

class DsBuilder : public RRBuilder {
    uint16_t keyTag{0};
    uint8_t algorithm{0};
    uint8_t digestType{0};

    DsBuilder(const std::string &name, DnsMessage::ClassType qclass = DnsMessage::ClassType::IN) : RRBuilder(name, DnsMessage::RecordType::DS, qclass) {}

    virtual void buildBody(DnsMessage &target, uint16_t lengthLocation) override {
        target.addShort(keyTag);
        target.addByte(algorithm);
        target.addByte(digestType);
        target.setAnswerCount(target.getAnswerCount() + 1);
        addSignature(target, lengthLocation);
    }

    void addSignature(DnsMessage &/*target*/, uint16_t /*lengthLocation*/) {
    }
};

#endif // DNS64SEC_DS_BUILDER_H