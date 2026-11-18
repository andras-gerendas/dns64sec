/**
 * @file Task.cc
 * @author Andras Attila Gerendas
 * @brief Class containing the state machine for DNS packet processing
 * @version 0.1
 * @date 2022-06-21
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "Task.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <sys/ioctl.h>
#include <syslog.h>

auto Task::createSocket(const sockaddr_storage &address, int *socket_descriptor) -> SocketCreationResult {
    const int descriptor = socket(address.ss_family, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);

    if (-1 == descriptor) {
        return SocketCreationResult::CREATION_FAILURE;
    }

    struct timeval timeout {};

    timeout.tv_sec = configuration.getTimeout().count() / SEC_MSEC;

    timeout.tv_usec = (configuration.getTimeout().count() % SEC_MSEC) * SEC_MSEC;

    if (setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        if (descriptor > -1) {
            close(descriptor);
        }

        return SocketCreationResult::RECEIVE_TIMEOUT_FAILURE;
    }

    if (setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        if (descriptor > -1) {
            close(descriptor);
        }

        return SocketCreationResult::SEND_TIMEOUT_FAILURE;
    }

    *socket_descriptor = descriptor;

    return SocketCreationResult::SUCCESS;
}

auto Task::handleNextResolverState() -> bool {
    attempt++;

    if (attempt < configuration.getAttempts()) {
        if (originalQueryType != DnsMessage::RecordType::NO_VALUE) {
            request_buffer.setQueryType(originalQueryType);

            originalQueryType = DnsMessage::RecordType::NO_VALUE;
        }

        socketType = SocketType::RESOLVER_SOCKET;
        state = TaskState::INITIAL;
        dnssecState = DnssecState::NON_DNSSEC;
        nextState = TaskState::INITIAL;
        nextDnssecState = DnssecState::NON_DNSSEC;

        if (query_socket > -1) {
            close(query_socket);
            query_socket = -1;
        }

        if (delegation_socket > -1) {
            close(delegation_socket);
            delegation_socket = -1;
        }

        if (!resetElapsedTime()) {
            syslog(LOG_ERR, "Could not reset timer");
            return true;
        }

        return false;
    }

    attempt = 0;

    if (currentResolver < static_cast<uint16_t>(UINT16_MAX)) {
        currentResolver++;
    }

    if (currentResolver >= configuration.getExternalResolvers().size()) {
        state = TaskState::FINISHED;
        return true;
    }

    syslog(LOG_DEBUG, "Attempting the request with the next resolver");

    state = TaskState::INITIAL;
    dnssecState = DnssecState::NON_DNSSEC;
    nextState = TaskState::INITIAL;
    nextDnssecState = DnssecState::NON_DNSSEC;

    if (query_socket > -1) {
        close(query_socket);
        query_socket = -1;
    }

    if (delegation_socket > -1) {
        close(delegation_socket);
        delegation_socket = -1;
    }

    if (originalQueryType != DnsMessage::RecordType::NO_VALUE) {
        request_buffer.setQueryType(originalQueryType);

        originalQueryType = DnsMessage::RecordType::NO_VALUE;
    }

    if (!resetElapsedTime()) {
        syslog(LOG_ERR, "Could not reset timer");
        return true;
    }

    return false;
}

auto Task::handleInitialState() -> bool {
    /* Sanity check */
    if (request_buffer.getType() == DnsMessage::QrType::RESPONSE) {
        syslog(LOG_WARNING, "Received a response instead of a query");
        state = TaskState::FINISHED;

        return true;
    }

    auto queryCount = request_buffer.getQueryCount();

    if (queryCount != 1) {
        syslog(LOG_WARNING, "The number of queries is not one (but %u)", queryCount);
        request_buffer.modifyQueryToBeResponse(DnsMessage::ResponseCode::FORMERR);
        state = TaskState::SEND_PACKET;
        currentBuffer = BufferType::REQUEST_BUFFER;
        currentQr = DnsMessage::QrType::RESPONSE;
        nextState = TaskState::FINISHED;

        return false;
    }

    if (!request_buffer.isOpCodeValid()) {
        request_buffer.modifyQueryToBeResponse(DnsMessage::ResponseCode::NOTIMP);
        state = TaskState::SEND_PACKET;
        currentBuffer = BufferType::REQUEST_BUFFER;
        currentQr = DnsMessage::QrType::RESPONSE;
        nextState = TaskState::FINISHED;

        return false;
    }

    DnsMessage::ResponseCode rcode = DnsMessage::ResponseCode::NOERROR;

    udpPayloadSize = request_buffer.updateUdpPayloadSize(configuration, &rcode);

    if (0 == udpPayloadSize) {
        request_buffer.modifyQueryToBeResponse(rcode);
        state = TaskState::SEND_PACKET;
        currentBuffer = BufferType::REQUEST_BUFFER;
        currentQr = DnsMessage::QrType::RESPONSE;
        nextState = TaskState::FINISHED;

        return false;
    }

    state = TaskState::CREATE_SOCKET;

    return false;
}

auto Task::handleCreateSocketState() -> bool {
    auto result = createSocket(configuration.getExternalResolvers()[currentResolver], &query_socket);

    switch (result) {
        case SocketCreationResult::RECEIVE_TIMEOUT_FAILURE:
            syslog(LOG_ERR, "Couldn't set query socket option for receive timeout %s", strerror(errno));
            return true;
        
        case SocketCreationResult::SEND_TIMEOUT_FAILURE:
            syslog(LOG_ERR, "Couldn't set query socket option for send timeout %s", strerror(errno));
            return true;
        
        case SocketCreationResult::SUCCESS:
            state = TaskState::SEND_PACKET;
            currentBuffer = BufferType::REQUEST_BUFFER;
            currentQr = DnsMessage::QrType::REQUEST;
            nextState = TaskState::PREPARE_FIRST_FORWARD;

            return false;

        /** Defaulting to CREATION_FAILURE */                                        
        default:
            syslog(LOG_INFO, "Couldn't create socket");
            return true;
    }
}

auto Task::handleSendPacketState() -> bool {
    errno = 0;

    if (!sendRequest(currentBuffer, currentQr)) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            syslog(LOG_ERR, "Couldn't send packet to %s, err: %s", currentQr == DnsMessage::QrType::REQUEST ? "resolver" : "client", strerror(errno));

            if (dnssecState == DnssecState::DS_AAAA_REQUEST) {
                socketType = SocketType::RESOLVER_SOCKET;
                state = nextState;
                dnssecState = DnssecState::NS_A_REQUEST;

                return false;
            }
        }

        return true;
    }

    syslog(LOG_DEBUG, "Sent packet to %s", currentQr == DnsMessage::QrType::REQUEST ? "resolver" : "client");

    state = nextState;
    dnssecState = nextDnssecState;

    return false;
}

auto Task::handleReceivePacketState() -> bool {
    if (!receivePacket(currentBuffer)) {
        return true;
    }

    state = nextState;
    dnssecState = nextDnssecState;

    syslog(LOG_DEBUG, "Received packet from resolver");

    if (configuration.isDnssecValidated() && dnssecState == DnssecState::NON_DNSSEC) {
        dnssecState = DnssecState::PREPARE_DNSSEC;
    }

    return false;
}

auto Task::handleFirstAnswerState() -> bool {
    if (answer_buffer.getType() == DnsMessage::QrType::REQUEST) {
        syslog(LOG_WARNING, "Received a query instead of a response");
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::ANSWER_BUFFER;
        nextState = TaskState::FIRST_ANSWER;
        return false;
    }

    auto [aaaaStart, aaaaAfterName] = DnsMessage::RecordParser(request_buffer).parseNext(DnsMessage::SectionType::QUESTION, DnsMessage::RecordType::AAAA);

    const bool hasAaaaIn = aaaaStart > 0 && request_buffer.getClassType(aaaaAfterName + 2) == DnsMessage::ClassType::IN;

    if (!answer_buffer.validateQuestionSection(request_buffer)) {
        syslog(LOG_DEBUG, "Query question section does not match first answer question section");
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::ANSWER_BUFFER;
        nextState = TaskState::FIRST_ANSWER;
        return false;
    }

    if (!hasAaaaIn || answer_buffer.hasRecordType(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::AAAA)) {
        if (!hasAaaaIn) {
            syslog(LOG_DEBUG, "Got non-AAAA answer");
        } else {
            syslog(LOG_DEBUG, "Got AAAA answer");
        }

        state = TaskState::SEND_PACKET;
        currentBuffer = BufferType::ANSWER_BUFFER;
        currentQr = DnsMessage::QrType::RESPONSE;
        nextState = TaskState::FINISHED;

        return false;
    }

    storeOriginalType(request_buffer);

    /* TODO: Reuse parts from the first answer and only request A record? */
    if (!request_buffer.setQueryType(DnsMessage::RecordType::A)) {
        syslog(LOG_ERR, "Couldn't set query to A");
        state = TaskState::FINISHED;
        return true;
    }

    state = TaskState::SEND_PACKET;
    currentBuffer = BufferType::REQUEST_BUFFER;
    currentQr = DnsMessage::QrType::REQUEST;
    nextState = TaskState::PREPARE_SECOND_FORWARD;
    return false;
}

auto Task::handleARequestSentState() -> bool {
    if (answer_buffer.getType() == DnsMessage::QrType::REQUEST) {
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::ANSWER_BUFFER;
        nextState = TaskState::A_REQUEST_SENT;
        syslog(LOG_WARNING, "Received a query instead of a response");
        return false;
    }

    if (!answer_buffer.validateQuestionSection(request_buffer)) {
        syslog(LOG_DEBUG, "Query question section does not match second answer question section");
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::ANSWER_BUFFER;
        nextState = TaskState::A_REQUEST_SENT;
        return false;
    }

    if (answer_buffer.hasRecordType(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::A)) {
        syslog(LOG_DEBUG, "Got A answer");

        /* TODO: Can't the request buffer be used for the forged answer? */
        if (nullptr == forged_buffer.getBuffer()) {
            forged_buffer.updateBuffer(std::make_unique<uint8_t[]>(udpPayloadSize), udpPayloadSize);
        }

        const bool isSynthesized = answer_buffer.generateSynthetisedMessage(configuration, &forged_buffer);

        sender_length = sizeof(sockaddr_in6);

        state = TaskState::SEND_PACKET;
        currentQr = DnsMessage::QrType::RESPONSE;
        nextState = TaskState::FINISHED;

        if (isSynthesized) {
            currentBuffer = BufferType::FORGED_BUFFER;
            forged_buffer.setTransactionID(request_buffer.getTransactionID());
        } else {
            request_buffer.modifyQueryToBeResponse(DnsMessage::ResponseCode::SERVFAIL);
            request_buffer.setQueryType(DnsMessage::RecordType::AAAA);

            currentBuffer = BufferType::REQUEST_BUFFER;
        }

        return false;
    }

    syslog(LOG_DEBUG, "Got no A answer, sending back not found");

    if (!answer_buffer.setQueryType(DnsMessage::RecordType::AAAA)) {
        state = TaskState::NEXT_RESOLVER;
        return false;
    }

    answer_buffer.setTransactionID(request_buffer.getTransactionID());

    state = TaskState::SEND_PACKET;
    currentBuffer = BufferType::ANSWER_BUFFER;
    currentQr = DnsMessage::QrType::RESPONSE;
    nextState = TaskState::FINISHED;

    return false;
}

auto Task::handlePrepareDnssecState() -> bool {
    if (copy_buffer.getBuffer() == nullptr) {
        copy_buffer.updateBuffer(std::make_unique<uint8_t[]>(udpPayloadSize), udpPayloadSize);
    }

    memcpy(copy_buffer.getBuffer(), request_buffer.getBuffer(), request_buffer.getSize());
    copy_buffer.setSize(request_buffer.getSize());

    dnssecState = DnssecState::DNSKEY_REQUEST;
    rrsigBuffer = BufferType::ANSWER_BUFFER;

    return false;
}

auto Task::handleDnskeyRequestState() -> bool {
    auto *answerMessage = getBufferByType(rrsigBuffer);

    if (answerMessage->getType() == DnsMessage::QrType::REQUEST) {
        syslog(LOG_WARNING, "Received a query instead of a response");
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::ANSWER_BUFFER;
        dnssecState = DnssecState::NON_DNSSEC;
        nextDnssecState = DnssecState::NON_DNSSEC;
        return false;
    }

    if (rrsigBuffer == BufferType::ANSWER_BUFFER && !answerMessage->validateQuestionSection(copy_buffer)) {
        syslog(LOG_DEBUG, "Query question section does not match first answer (dnssec) question section");
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::ANSWER_BUFFER;
        dnssecState = DnssecState::NON_DNSSEC;
        nextDnssecState = DnssecState::NON_DNSSEC;
        return false;
    }

    auto [rrsigStart, rrsigAfterName] = DnsMessage::RecordParser(*answerMessage).parseNext(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::RRSIG);

    if (0 == rrsigStart) {
        syslog(LOG_DEBUG, "DNSSEC validation requested, but RRSIG not found");
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::ANSWER_BUFFER;
        dnssecState = DnssecState::NON_DNSSEC;
        nextDnssecState = DnssecState::NON_DNSSEC;
        return false;
    }

    auto *rrsigHeader = answerMessage->getRrsigHeader(rrsigAfterName);

    if (!answerMessage->validateRrSigTimestamp(rrsigAfterName)) {
        syslog(LOG_DEBUG, "RRSIG timestamp out of range");
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::ANSWER_BUFFER;
        dnssecState = DnssecState::NON_DNSSEC;
        nextDnssecState = DnssecState::NON_DNSSEC;
        return false;
    }

    storeOriginalType(copy_buffer);

    const uint16_t typeCovered = rrsigHeader->rdata.getTypeCovered();

    if (originalQueryType != static_cast<DnsMessage::RecordType>(typeCovered)) {
        syslog(LOG_DEBUG, "RRSIG (%u) does not cover original type (%u)", typeCovered, static_cast<uint16_t>(originalQueryType));
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::ANSWER_BUFFER;
        dnssecState = DnssecState::NON_DNSSEC;
        nextDnssecState = DnssecState::NON_DNSSEC;
        return false;
    }

    if (key_request_buffer.getBuffer() == nullptr) {
        key_request_buffer.updateBuffer(std::make_unique<uint8_t[]>(udpPayloadSize), udpPayloadSize);
    }

    if (answerMessage->compareLabelListsBinary(DnsMessage::DNS_HEADER_LENGTH, rrsigAfterName + DnsMessage::LEN_RRSIG_FIXED) != 0) {
        syslog(LOG_DEBUG, "RRSIG Signer's name is not equal to question name");
        const uint16_t qnameEnd = copy_buffer.getNamePosition(DnsMessage::DNS_HEADER_LENGTH);
        const uint16_t signerNameEnd = answerMessage->getNamePosition(rrsigAfterName + DnsMessage::LEN_RRSIG_FIXED);

        memcpy(key_request_buffer.getBuffer(), copy_buffer.getBuffer(), DnsMessage::DNS_HEADER_LENGTH);
        
        uint16_t position = DnsMessage::DNS_HEADER_LENGTH;

        memcpy(&key_request_buffer.getBuffer()[position],
                &answerMessage->getBuffer()[rrsigAfterName + DnsMessage::LEN_RRSIG_FIXED], signerNameEnd - rrsigAfterName - DnsMessage::LEN_RRSIG_FIXED);

        position += signerNameEnd - rrsigAfterName - DnsMessage::LEN_RRSIG_FIXED;

        memcpy(&key_request_buffer.getBuffer()[position], &copy_buffer.getBuffer()[qnameEnd], copy_buffer.getSize() - qnameEnd);

        position += copy_buffer.getSize() - qnameEnd;

        key_request_buffer.setSize(position);
    } else {
        copy_buffer.copyBuffer(&key_request_buffer);
    }

    if (!key_request_buffer.setQueryType(DnsMessage::RecordType::DNSKEY)) {
        state = TaskState::FINISHED;
        return true;
    }

    if (!resetElapsedTime()) {
        syslog(LOG_ERR, "Could not reset timer");
        return true;
    }

    state = TaskState::SEND_PACKET;
    currentBuffer = BufferType::KEY_REQUEST_BUFFER;
    currentQr = DnsMessage::QrType::REQUEST;
    nextDnssecState = DnssecState::PREPARE_DNSKEY;

    return false;
}

auto Task::handleDnskeyResponseState() -> bool {
    auto *answerMessage = getBufferByType(rrsigBuffer);

    if (key_answer_buffer.getType() == DnsMessage::QrType::REQUEST) {
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::KEY_ANSWER_BUFFER;
        nextDnssecState = DnssecState::DNSKEY_RESPONSE;
        syslog(LOG_WARNING, "Received a query instead of a response");
        return false;
    }

    if (!key_answer_buffer.validateQuestionSection(key_request_buffer)) {
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::KEY_ANSWER_BUFFER;
        nextDnssecState = DnssecState::DNSKEY_RESPONSE;
        syslog(LOG_DEBUG, "Query question section does not match dnskey answer question section");
        return false;
    }

    if (!key_answer_buffer.hasRecordType(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::DNSKEY)) {
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::KEY_ANSWER_BUFFER;
        nextDnssecState = DnssecState::DNSKEY_RESPONSE;
        syslog(LOG_DEBUG, "DNSSEC validation requested, but DNSKEY not found");
        return false;
    }

    syslog(LOG_DEBUG, "Got DNSKEY answer");

    auto [rrsigStart, rrsigAfterName] = DnsMessage::RecordParser(*answerMessage).parseNext(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::RRSIG);

    auto validationResult = answerMessage->validateRrSigSignature(originalQueryType, rrsigAfterName, key_answer_buffer);

    if (validationResult == DnsMessage::SignatureValidationResult::KEY_NOT_FOUND) {
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::KEY_ANSWER_BUFFER;
        nextDnssecState = DnssecState::DNSKEY_RESPONSE;
        syslog(LOG_DEBUG, "Could not find matching DNSKEY for ZSK");
        return false;
    }

    if (validationResult == DnsMessage::SignatureValidationResult::TYPE_COVERED_INVALID) {
        syslog(LOG_DEBUG, "RRSIG does not cover original type for ZSK");
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::ANSWER_BUFFER;
        dnssecState = DnssecState::NON_DNSSEC;
        nextDnssecState = DnssecState::NON_DNSSEC;
        return false;
    }

    /** TODO: Should this be here, or conditionally in DNSKEY_REQUEST? */
    if (validationResult == DnsMessage::SignatureValidationResult::TIMESTAMP_INVALID) {
        syslog(LOG_DEBUG, "RRSIG timestamp out of range for ZSK");
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::ANSWER_BUFFER;
        dnssecState = DnssecState::NON_DNSSEC;
        nextDnssecState = DnssecState::NON_DNSSEC;
        return false;
    }

    syslog(LOG_DEBUG, "RRSet validation successful");

    DnsMessage::RecordParser key_answer_parser(key_answer_buffer);

    while (true) {
        auto [rrsigStart, rrsigAfterName] = key_answer_parser.parseNext(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::RRSIG);

        if (rrsigAfterName == 0) {
            syslog(LOG_DEBUG, "None of the RRSIG and DNSKEY pairs worked for KSK");
            state = TaskState::RECEIVE_PACKET;
            currentBuffer = BufferType::ANSWER_BUFFER;
            dnssecState = DnssecState::NON_DNSSEC;
            nextDnssecState = DnssecState::NON_DNSSEC;
            return false;
        }

        auto validationResult = key_answer_buffer.validateRrSigSignature(DnsMessage::RecordType::DNSKEY, rrsigAfterName, key_answer_buffer);

        if (validationResult == DnsMessage::SignatureValidationResult::KEY_NOT_FOUND) {
            syslog(LOG_DEBUG, "Could not find matching DNSKEY for KSK");
            continue;
        }

        if (validationResult == DnsMessage::SignatureValidationResult::TYPE_COVERED_INVALID) {
            syslog(LOG_DEBUG, "RRSIG does not cover DNSKEY as original type for KSK");
            continue;
        }

        /** TODO: Should this be here, or conditionally in DNSKEY_REQUEST? */
        if (validationResult == DnsMessage::SignatureValidationResult::TIMESTAMP_INVALID) {
            syslog(LOG_DEBUG, "RRSIG timestamp out of range for KSK");
            continue;
        }

        /** One valid signature is enough, cannot distinguish between signatures */
        if (validationResult == DnsMessage::SignatureValidationResult::SUCCESS) {
            break;
        }
    }

    syslog(LOG_DEBUG, "Zone validation successful");

    if (key_request_buffer.getBuffer()[DnsMessage::DNS_HEADER_LENGTH] == 0) {
        if (!resetElapsedTime()) {
            syslog(LOG_ERR, "Could not reset timer");
            return true;
        }

        syslog(LOG_DEBUG, "Delegation validation successful");

        key_request_buffer.setQueryType(originalQueryType);

        socketType = SocketType::RESOLVER_SOCKET;
        dnssecState = DnssecState::NON_DNSSEC;
        nextDnssecState = DnssecState::NON_DNSSEC;

        return false;
    }

    if (!resetElapsedTime()) {
        syslog(LOG_ERR, "Could not reset timer");
        return true;
    }

    dnssecState = DnssecState::NS_LIST_REQUEST;

    return false;
}

auto Task::handleNsListRequestState() -> bool {
    state = TaskState::SEND_PACKET;
    currentBuffer = BufferType::KEY_REQUEST_BUFFER;
    currentQr = DnsMessage::QrType::REQUEST;
    nextDnssecState = DnssecState::PREPARE_NS_LIST;

    if (!copy_buffer.copyLabelListAsParent(&key_request_buffer)) {
        state = TaskState::NEXT_RESOLVER;
        return false;
    }

    if (!key_request_buffer.setQueryType(DnsMessage::RecordType::NS)) {
        state = TaskState::NEXT_RESOLVER;
        return false;
    }

    return false;
}

auto Task::handleNsListResponseState() -> bool {
    if (list_buffer.getType() == DnsMessage::QrType::REQUEST) {
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::LIST_BUFFER;
        nextDnssecState = DnssecState::NS_LIST_RESPONSE;
        syslog(LOG_WARNING, "Received an ns query instead of a response");
        return false;
    }

    if (!list_buffer.validateQuestionSection(key_request_buffer)) {
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::LIST_BUFFER;
        nextDnssecState = DnssecState::NS_LIST_RESPONSE;
        syslog(LOG_DEBUG, "Query question section does not match ds answer question section");
        return false;
    }

    if (!list_buffer.hasRecordType(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::NS)) {
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::LIST_BUFFER;
        nextDnssecState = DnssecState::NS_LIST_RESPONSE;
        syslog(LOG_DEBUG, "DNSSEC validation requested, but NS not found");
        return false;
    }

    syslog(LOG_DEBUG, "NS list acquired");
    dnssecState = DnssecState::NS_AAAA_REQUEST;

    return false;
}

auto Task::handleNsAaaaRequestState() -> bool {
    auto [nsStart, nsAfterName] = DnsMessage::RecordParser(list_buffer).parseNext(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::NS);

    const uint16_t labelEndPosition = copy_buffer.getNamePosition(DnsMessage::DNS_HEADER_LENGTH);

    uint16_t position = DnsMessage::DNS_HEADER_LENGTH;

    memcpy(key_request_buffer.getBuffer(), copy_buffer.getBuffer(), DnsMessage::DNS_HEADER_LENGTH);

    position = list_buffer.expandName(key_request_buffer.getBuffer(), DnsMessage::DNS_HEADER_LENGTH, nsAfterName + DnsMessage::LEN_RR_FIXED);

    memcpy(&key_request_buffer.getBuffer()[position], &copy_buffer.getBuffer()[labelEndPosition], copy_buffer.getSize() - labelEndPosition);

    position += copy_buffer.getSize() - labelEndPosition;

    key_request_buffer.setSize(position);

    if (!key_request_buffer.setQueryType(DnsMessage::RecordType::AAAA)) {
        state = TaskState::NEXT_RESOLVER;
        return false;
    }

    if (!resetElapsedTime()) {
        syslog(LOG_ERR, "Could not reset timer");
        return true;
    }

    state = TaskState::SEND_PACKET;
    currentBuffer = BufferType::KEY_REQUEST_BUFFER;
    currentQr = DnsMessage::QrType::REQUEST;
    nextDnssecState = DnssecState::PREPARE_NS_AAAA;

    return false;
}

auto Task::handleNsAaaaResponseState() -> bool {
    if (address_buffer.getType() == DnsMessage::QrType::REQUEST) {
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::ADDRESS_BUFFER;
        nextDnssecState = DnssecState::NS_AAAA_RESPONSE;
        syslog(LOG_WARNING, "Received an ns aaaa query instead of a response");
        return false;
    }

    if (!address_buffer.validateQuestionSection(key_request_buffer)) {
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::ADDRESS_BUFFER;
        nextDnssecState = DnssecState::NS_AAAA_RESPONSE;
        syslog(LOG_DEBUG, "Query question section does not match ds answer question section");
        return false;
    }

    if (!address_buffer.hasRecordType(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::AAAA)) {
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::ADDRESS_BUFFER;
        nextDnssecState = DnssecState::NS_AAAA_RESPONSE;
        syslog(LOG_DEBUG, "DNSSEC validation requested, but NS AAAA not found");
        return false;
    }

    auto [aaaaStart, aaaaAfterName] = DnsMessage::RecordParser(address_buffer).parseNext(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::AAAA);

    memcpy(&(reinterpret_cast<sockaddr_in6*>(&delegation_address)->sin6_addr),
        &address_buffer.getBuffer()[aaaaAfterName + DnsMessage::LEN_RR_FIXED], DnsMessage::LEN_IPV6_ADDR);

    reinterpret_cast<sockaddr_in6*>(&delegation_address)->sin6_port = htons(Configuration::DELEGATION_DNS_PORT);

    delegation_address.ss_family = AF_INET6;

    syslog(LOG_DEBUG, "Delegator NS AAAA found");
    dnssecState = DnssecState::DS_AAAA_REQUEST;

    return false;
}

auto Task::handleNsARequestState() -> bool {
    if (!key_request_buffer.setQueryType(DnsMessage::RecordType::A)) {
        state = TaskState::NEXT_RESOLVER;
        return false;
    }

    if (!resetElapsedTime()) {
        syslog(LOG_ERR, "Could not reset timer");
        return true;
    }

    state = TaskState::SEND_PACKET;
    currentBuffer = BufferType::KEY_REQUEST_BUFFER;
    currentQr = DnsMessage::QrType::REQUEST;
    nextDnssecState = DnssecState::PREPARE_NS_A;

    return false;
}

auto Task::handleNsAResponseState() -> bool {
    if (address_buffer.getType() == DnsMessage::QrType::REQUEST) {
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::ADDRESS_BUFFER;
        nextDnssecState = DnssecState::NS_A_RESPONSE;
        syslog(LOG_WARNING, "Received an ns a query instead of a response");
        return false;
    }

    if (!address_buffer.validateQuestionSection(key_request_buffer)) {
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::ADDRESS_BUFFER;
        nextDnssecState = DnssecState::NS_A_RESPONSE;
        syslog(LOG_DEBUG, "Query question section does not match ns a answer question section");
        return false;
    }

    if (!address_buffer.hasRecordType(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::A)) {
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::ADDRESS_BUFFER;
        nextDnssecState = DnssecState::NS_A_RESPONSE;
        syslog(LOG_DEBUG, "DNSSEC validation requested, but NS A not found");
        return false;
    }

    auto [aStart, aAfterName] = DnsMessage::RecordParser(address_buffer).parseNext(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::A);

    memcpy(&(reinterpret_cast<sockaddr_in*>(&delegation_address)->sin_addr), &address_buffer.getBuffer()[aAfterName + DnsMessage::LEN_RR_FIXED], 4);

    reinterpret_cast<sockaddr_in*>(&delegation_address)->sin_port = htons(Configuration::DELEGATION_DNS_PORT);

    delegation_address.ss_family = AF_INET;

    syslog(LOG_DEBUG, "Delegator NS A found");
    dnssecState = DnssecState::DS_A_REQUEST;

    return false;
}

auto Task::handleDsRequest() -> bool {
    auto result = createSocket(delegation_address, &delegation_socket);

    switch (result) {
        case SocketCreationResult::RECEIVE_TIMEOUT_FAILURE:
            syslog(LOG_ERR, "Couldn't set delegation socket option for receive timeout %s", strerror(errno));
            return true;
        
        case SocketCreationResult::SEND_TIMEOUT_FAILURE:
            syslog(LOG_ERR, "Couldn't set delegation socket option for send timeout %s", strerror(errno));
            return true;
        
        case SocketCreationResult::SUCCESS:
            storeOriginalType(copy_buffer);

            if (!copy_buffer.setQueryType(DnsMessage::RecordType::DS)) {
                syslog(LOG_ERR, "Couldn't set query to DS");
                state = TaskState::FINISHED;
                return true;
            }

            if (!resetElapsedTime()) {
                syslog(LOG_ERR, "Could not reset timer");
                return true;
            }

            socketType = SocketType::DELEGATION_SOCKET;
            state = TaskState::SEND_PACKET;
            currentBuffer = BufferType::COPY_BUFFER;
            currentQr = DnsMessage::QrType::REQUEST;
            nextDnssecState = DnssecState::PREPARE_DS;

            syslog(LOG_DEBUG, "Created socket for DS request");

            return false;

        /** Defaulting to CREATION_FAILURE */                                        
        default:
            syslog(LOG_INFO, "Couldn't create delegation socket");
            return true;
    }
}

auto Task::handleDsResponse() -> bool {
    if (ds_buffer.getType() == DnsMessage::QrType::REQUEST) {
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::DS_BUFFER;
        nextDnssecState = DnssecState::DS_RESPONSE;
        syslog(LOG_WARNING, "Received a ds query instead of a response");
        return false;
    }

    if (!ds_buffer.validateQuestionSection(copy_buffer)) {
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::DS_BUFFER;
        nextDnssecState = DnssecState::DS_RESPONSE;
        syslog(LOG_DEBUG, "Query question section does not match ds answer question section");
        return false;
    }

    if (!ds_buffer.hasRecordType(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::DS)) {
        state = TaskState::RECEIVE_PACKET;
        currentBuffer = BufferType::DS_BUFFER;
        nextDnssecState = DnssecState::DS_RESPONSE;
        syslog(LOG_DEBUG, "DNSSEC validation requested, but DS not found");
        return false;
    }

    bool dsValidated = false;

    DnsMessage::RecordParser ds_parser(ds_buffer);

    while (!dsValidated) {
        auto [dsStart, dsAfterName] = ds_parser.parseNext(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::DS);

        auto *dsHeader = ds_buffer.getDsHeader(dsAfterName);

        DnsMessage::RecordParser key_answer_parser(key_answer_buffer);

        while (!dsValidated) {
            auto [dnsKeyStart, dnsKeyAfterName] = key_answer_parser.parseNext(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::DNSKEY);

            if (0 == dnsKeyAfterName) {
                state = TaskState::RECEIVE_PACKET;
                currentBuffer = BufferType::DS_BUFFER;
                nextDnssecState = DnssecState::DS_RESPONSE;
                syslog(LOG_DEBUG, "Could not find matching DNSKEY for DS");
                return false;
            }

            auto *dnsKeyHeader = key_answer_buffer.getDnsKeyHeader(dnsKeyAfterName);

            /* DNSKEY has to be a zone key to be used for validation */
            if (!dnsKeyHeader->isZoneKey) {
                syslog(LOG_DEBUG, "DNSKEY is not a zone key");
                continue;
            }

            if (dnsKeyHeader->algorithm != dsHeader->rdata.algorithm) {
                syslog(LOG_DEBUG, "The algorithms of DNSKEY (%u) and DS (%u) do not match", dnsKeyHeader->algorithm, dsHeader->rdata.algorithm);
                continue;
            }

            if (dsHeader->rdata.digestType != static_cast<uint8_t>(DnsMessage::DigestType::SHA256)) {
                syslog(LOG_DEBUG, "Unsupported digest type (%u)", dsHeader->rdata.digestType);
                continue;
            }

            auto keyTag = key_answer_buffer.calculateKeyTag(dnsKeyAfterName);
            auto dsTag = dsHeader->rdata.getKeyTag();

            if (keyTag != dsTag) {
                syslog(LOG_DEBUG, "The key tags of DNSKEY (%u) and DS (%u) do not match", keyTag, dsTag);
                continue;
            }

            syslog(LOG_DEBUG, "DNSKEY and DS match, keytag: %u, algo: %u, digest: %u", keyTag, dnsKeyHeader->algorithm, dsHeader->rdata.digestType);

            auto signatureBuffer = std::make_unique<uint8_t[]>(DnsMessage::MAX_LEN_SIG_BUFFER);

            auto position = key_answer_buffer.expandName(signatureBuffer.get(), 0, dnsKeyStart);

            memcpy(&signatureBuffer[position], &key_answer_buffer.getBuffer()[dnsKeyAfterName + DnsMessage::LEN_RR_FIXED], dnsKeyHeader->header.getLength());

            position += dnsKeyHeader->header.getLength();

            std::array<unsigned char, SHA256_DIGEST_LENGTH> hash{};

            EVP_MD_CTX *mdctx = EVP_MD_CTX_create();

            EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
            EVP_DigestUpdate(mdctx, signatureBuffer.get(), position);
            EVP_DigestFinal_ex(mdctx, hash.data(), nullptr);

            EVP_MD_CTX_destroy(mdctx);

            const int result = memcmp(hash.data(), &(dsHeader->rdata.digestType) + 1, SHA256_DIGEST_LENGTH);

            if (result == 0) {
                dsValidated = true;

                if (!resetElapsedTime()) {
                    syslog(LOG_ERR, "Could not reset timer");
                    return true;
                }

                if (copy_buffer.getBuffer()[DnsMessage::DNS_HEADER_LENGTH] == 0) {
                    syslog(LOG_ERR, "Request to go higher than root domain");
                    continue;
                }

                if (!copy_buffer.copyLabelListAsParent(&key_request_buffer)) {
                    syslog(LOG_ERR, "Could not perform label list copy for parent check");
                    continue;
                }

                syslog(LOG_DEBUG, "Layer validation complete, going up a layer");

                key_request_buffer.copyBuffer(&copy_buffer);

                originalQueryType = DnsMessage::RecordType::NO_VALUE;

                storeOriginalType(copy_buffer);

                socketType = SocketType::RESOLVER_SOCKET;
                dnssecState = DnssecState::DNSKEY_REQUEST;
                rrsigBuffer = BufferType::DS_BUFFER;

                return false;
            }
            
            syslog(LOG_DEBUG, "Hash does not match");
        }
    }

    return false;
}

/* TODO: Implement random-access of resolvers (round-robin makes no sense as it would require thread syncing)
         Random-access has to be linear */
auto Task::handleState() -> bool {
    switch (state) {
        case TaskState::NEXT_RESOLVER:
            return handleNextResolverState();

        case TaskState::INITIAL:
            return handleInitialState();

        case TaskState::CREATE_SOCKET:
            return handleCreateSocketState();

        case TaskState::PREPARE_FIRST_FORWARD: {
            if (nullptr == answer_buffer.getBuffer()) {
                answer_buffer.updateBuffer(std::make_unique<uint8_t[]>(udpPayloadSize), udpPayloadSize);
            }

            state = TaskState::RECEIVE_PACKET;
            currentBuffer = BufferType::ANSWER_BUFFER;
            nextState = TaskState::FIRST_ANSWER;

            return false;
        }

        case TaskState::PREPARE_SECOND_FORWARD: {
            state = TaskState::RECEIVE_PACKET;
            currentBuffer = BufferType::ANSWER_BUFFER;
            nextState = TaskState::A_REQUEST_SENT;

            return false;
        }

        case TaskState::SEND_PACKET:
            return handleSendPacketState();

        case TaskState::RECEIVE_PACKET:
            return handleReceivePacketState();

        case TaskState::FIRST_ANSWER: {
            if (dnssecState != DnssecState::NON_DNSSEC) {
                break;
            }

            return handleFirstAnswerState();
        }

        case TaskState::A_REQUEST_SENT: {
            if (dnssecState != DnssecState::NON_DNSSEC) {
                break;
            }

            return handleARequestSentState();
        }

        case TaskState::FINISHED: {
            return true;
        }

        default:
            /* Unknown state results in an exit from the loop */
            state = TaskState::FINISHED;
            return true;
    }

    switch (dnssecState) {
        case DnssecState::PREPARE_DNSSEC:
            return handlePrepareDnssecState();

        case DnssecState::DNSKEY_REQUEST:
            return handleDnskeyRequestState();

        case DnssecState::PREPARE_DNSKEY: {
            if (nullptr == key_answer_buffer.getBuffer()) {
                key_answer_buffer.updateBuffer(std::make_unique<uint8_t[]>(udpPayloadSize), udpPayloadSize);
            }

            state = TaskState::RECEIVE_PACKET;
            currentBuffer = BufferType::KEY_ANSWER_BUFFER;
            nextDnssecState = DnssecState::DNSKEY_RESPONSE;

            return false;
        }

        case DnssecState::DNSKEY_RESPONSE:
            return handleDnskeyResponseState();

        case DnssecState::NS_LIST_REQUEST:
            return handleNsListRequestState();

        case DnssecState::PREPARE_NS_LIST: {
            if (nullptr == list_buffer.getBuffer()) {
                list_buffer.updateBuffer(std::make_unique<uint8_t[]>(udpPayloadSize), udpPayloadSize);
            }

            state = TaskState::RECEIVE_PACKET;
            currentBuffer = BufferType::LIST_BUFFER;
            nextDnssecState = DnssecState::NS_LIST_RESPONSE;

            return false;
        }

        case DnssecState::NS_LIST_RESPONSE:
            return handleNsListResponseState();

        case DnssecState::NS_AAAA_REQUEST:
            return handleNsAaaaRequestState();

        case DnssecState::PREPARE_NS_AAAA: {
            if (nullptr == address_buffer.getBuffer()) {
                address_buffer.updateBuffer(std::make_unique<uint8_t[]>(udpPayloadSize), udpPayloadSize);
            }

            state = TaskState::RECEIVE_PACKET;
            currentBuffer = BufferType::ADDRESS_BUFFER;
            nextDnssecState = DnssecState::NS_AAAA_RESPONSE;

            return false;
        }

        case DnssecState::NS_AAAA_RESPONSE:
            return handleNsAaaaResponseState();

        case DnssecState::NS_A_REQUEST:
            return handleNsARequestState();

        case DnssecState::PREPARE_NS_A: {
            if (nullptr == address_buffer.getBuffer()) {
                address_buffer.updateBuffer(std::make_unique<uint8_t[]>(udpPayloadSize), udpPayloadSize);
            }

            state = TaskState::RECEIVE_PACKET;
            currentBuffer = BufferType::ADDRESS_BUFFER;
            nextDnssecState = DnssecState::NS_A_RESPONSE;

            return false;
        }

        case DnssecState::NS_A_RESPONSE:
            return handleNsAResponseState();

        case DnssecState::DS_A_REQUEST:
            return handleDsRequest();

        case DnssecState::DS_AAAA_REQUEST:
            return handleDsRequest();

        case DnssecState::PREPARE_DS: {
            if (nullptr == ds_buffer.getBuffer()) {
                ds_buffer.updateBuffer(std::make_unique<uint8_t[]>(udpPayloadSize), udpPayloadSize);
            }

            socketType = SocketType::DELEGATION_SOCKET;
            state = TaskState::RECEIVE_PACKET;
            currentBuffer = BufferType::DS_BUFFER;
            nextDnssecState = DnssecState::DS_RESPONSE;

            return false;
        }

        case DnssecState::DS_RESPONSE:
            return handleDsResponse();

        default:
            /* Unknown state results in an exit from the loop */
            state = TaskState::FINISHED;
            return true;
    }
}

void Task::handleStateWrapper() {
    while (!handleState()) {};
}

auto Task::getBufferByType(BufferType type) -> DnsMessage * {
    switch(type) {
        case BufferType::REQUEST_BUFFER:
            return &request_buffer;

        case BufferType::ANSWER_BUFFER:
            return &answer_buffer;
        
        case BufferType::COPY_BUFFER:
            return &copy_buffer;
        
        case BufferType::KEY_REQUEST_BUFFER:
            return &key_request_buffer;

        case BufferType::KEY_ANSWER_BUFFER:
            return &key_answer_buffer;
        
        case BufferType::LIST_BUFFER:
            return &list_buffer;
        
        case BufferType::ADDRESS_BUFFER:
            return &address_buffer;

        case BufferType::DS_BUFFER:
            return &ds_buffer;

        case BufferType::FORGED_BUFFER:
            return &forged_buffer;
        
        default:
            return nullptr;
    }
}

void Task::setBufferByType(BufferType type, std::unique_ptr<uint8_t[]> buffer, ssize_t capacity) {
    DnsMessage *message = getBufferByType(type);

    if (message == nullptr) {
        return;
    }

    message->updateBuffer(std::move(buffer), capacity);
}

auto Task::receivePacket(BufferType type) -> bool {
    int current_socket;

    switch (socketType) {
        case SocketType::RESOLVER_SOCKET:
            current_socket = query_socket;
            break;

        case SocketType::DELEGATION_SOCKET:
            current_socket = delegation_socket;
            break;
    }

    int count{};
    ioctl(current_socket, FIONREAD, &count);

    if (count == 0) {
        return false;
    }

    DnsMessage *buffer = getBufferByType(type);

    if (nullptr == buffer) {
        syslog(LOG_DEBUG, "Couldn't get buffer by type during receive");
        state = TaskState::NEXT_RESOLVER;
        return false;
    }

    const ssize_t temp_receive_length = recv(current_socket, buffer->getBuffer(), udpPayloadSize, 0);

    if (DnsMessage::DNS_HEADER_LENGTH > temp_receive_length) {
        if (0 < temp_receive_length) {
            return false; /* Packet with invalid header, waiting for another one */
        }

        syslog(LOG_ERR, "Couldn't receive query from resolver, err: %s", strerror(errno));
        state = TaskState::NEXT_RESOLVER;
        return false;
    }

    buffer->setSize(temp_receive_length);

    return true;
}

auto Task::sendRequest(BufferType type, DnsMessage::QrType qrType) -> bool {
    const DnsMessage *buffer = getBufferByType(type);

    if (nullptr == buffer) {
        return false; /* Avoiding double error message */
    }

    int socket;
    const sockaddr *address;
    socklen_t address_size;

    if (DnsMessage::QrType::REQUEST == qrType) {
        if (SocketType::RESOLVER_SOCKET == socketType) {
            const auto &resolver = configuration.getExternalResolvers()[currentResolver];

            socket = query_socket;
            address = reinterpret_cast<const sockaddr *>(&resolver);
            address_size = sizeof(resolver);
        } else {
            socket = delegation_socket;
            address = reinterpret_cast<const sockaddr *>(&delegation_address);
            address_size = sizeof(delegation_address);
        }
    } else {
        socket = receiver_socket;
        address = reinterpret_cast<const sockaddr *>(&sender);
        address_size = sender_length;
    }

    const size_t whole_length = buffer->getSize();

    /* TODO: Send the A and the AAAA query concurrently */
    size_t all_sent_bytes = 0;
    ssize_t current_sent_bytes = 0;

    while (all_sent_bytes < whole_length) {
        current_sent_bytes = sendto(socket, &buffer->getBuffer()[all_sent_bytes], whole_length - all_sent_bytes, 0, address, address_size);

        if (0 >= current_sent_bytes) {
            return false; /* Avoiding double error message */
        }

        all_sent_bytes += current_sent_bytes;
    }

    return true;
}

void Task::printState() {
    /* Speeding up the check for non-debug log levels */
    if (Configuration::LogLevel::DEBUG != configuration.getLogLevel()) {
        return;
    }

    if (state == TaskState::SEND_PACKET) {
        syslog(LOG_DEBUG, "State: Send packet");
        return;
    }

    if (state == TaskState::RECEIVE_PACKET) {
        syslog(LOG_DEBUG, "State: Receive packet");
        return;
    }

    if (dnssecState != DnssecState::NON_DNSSEC) {
        switch (dnssecState) {
            case DnssecState::DNSKEY_REQUEST:
                syslog(LOG_DEBUG, "State: Assemble DNSKEY request");
                return;

            case DnssecState::PREPARE_DNSKEY:
                syslog(LOG_DEBUG, "State: Prepare DNSKEY response");
                return;

            case DnssecState::DNSKEY_RESPONSE:
                syslog(LOG_DEBUG, "State: Got DNSKEY answer");
                return;

            case DnssecState::DS_A_REQUEST:
                syslog(LOG_DEBUG, "State: Assemble DS request");
                return;

            case DnssecState::PREPARE_DS:
                syslog(LOG_DEBUG, "State: Prepare DS response");
                return;

            case DnssecState::DS_RESPONSE:
                syslog(LOG_DEBUG, "State: Got DS answer");
                return;

            default:
                syslog(LOG_DEBUG, "State: Unknown DNSSEC state");
                return;
        }
    }

    switch(state) {
        case TaskState::INITIAL:
            syslog(LOG_DEBUG, "State: Initial");
            return;

        case TaskState::CREATE_SOCKET:
            syslog(LOG_DEBUG, "Create socket");
            return;

        case TaskState::PREPARE_FIRST_FORWARD:
            syslog(LOG_DEBUG, "State: Prepare first forward");
            return;

        case TaskState::PREPARE_SECOND_FORWARD:
            syslog(LOG_DEBUG, "State: Prepare second forward");
            return;

        case TaskState::FIRST_ANSWER:
            syslog(LOG_DEBUG, "State: Got first answer");
            return;

        case TaskState::A_REQUEST_SENT:
            syslog(LOG_DEBUG, "State: A request sent");
            return;

        case TaskState::NEXT_RESOLVER:
            syslog(LOG_DEBUG, "State: Next resolver");
            return;

        case TaskState::FINISHED:
            syslog(LOG_DEBUG, "State: Finished");
            return;

        default:
            syslog(LOG_DEBUG, "State: Unknown state");
    }
}