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

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <sys/ioctl.h>
#include <syslog.h>

/* TODO: Implement random-access of resolvers (round-robin makes no sense as it would require thread syncing)
         Random-access has to be linear */
auto Task::handleState() -> bool {
    switch (state) {
        case TaskState::NEXT_RESOLVER: {
            attempt++;

            if (attempt < configuration.getAttempts()) {
                if (originalQueryType != DnsMessage::RecordType::NO_VALUE) {
                    DnsMessage dns_request(req_buffer.get(), receive_length);

                    dns_request.setQueryType(originalQueryType);

                    originalQueryType = DnsMessage::RecordType::NO_VALUE;
                }

                state = TaskState::INITIAL;
                dnssecState = DnssecState::NON_DNSSEC;
                nextState = TaskState::INITIAL;
                nextDnssecState = DnssecState::NON_DNSSEC;

                if (query_socket > -1) {
                    close(query_socket);
                    query_socket = -1;
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

            if (originalQueryType != DnsMessage::RecordType::NO_VALUE) {
                DnsMessage dns_request(req_buffer.get(), receive_length);

                dns_request.setQueryType(originalQueryType);

                originalQueryType = DnsMessage::RecordType::NO_VALUE;
            }

            if (!resetElapsedTime()) {
                syslog(LOG_ERR, "Could not reset timer");
                return true;
            }

            return false;
        }

        case TaskState::INITIAL: {
            DnsMessage aaaa_request(req_buffer.get(), receive_length);

            /* Sanity check */
            if (aaaa_request.getType() == DnsMessage::QrType::RESPONSE) {
                syslog(LOG_WARNING, "Received a response instead of a query");
                state = TaskState::FINISHED;

                return true;
            }

            auto queryCount = aaaa_request.getQueryCount();

            if (queryCount != 1) {
                syslog(LOG_WARNING, "The number of queries is not one (but %u)", queryCount);
                aaaa_request.modifyQueryToBeResponse(DnsMessage::ResponseCode::FORMERR);
                state = TaskState::SEND_PACKET;
                currentBuffer = BufferType::REQUEST_BUFFER;
                currentQr = DnsMessage::QrType::RESPONSE;
                nextState = TaskState::FINISHED;

                return false;
            }

            if (!aaaa_request.isOpCodeValid()) {
                aaaa_request.modifyQueryToBeResponse(DnsMessage::ResponseCode::NOTIMP);
                state = TaskState::SEND_PACKET;
                currentBuffer = BufferType::REQUEST_BUFFER;
                currentQr = DnsMessage::QrType::RESPONSE;
                nextState = TaskState::FINISHED;

                return false;
            }

            DnsMessage::ResponseCode rcode = DnsMessage::ResponseCode::NOERROR;

            udpPayloadSize = aaaa_request.updateUdpPayloadSize(configuration, &rcode);

            if (0 == udpPayloadSize) {
                aaaa_request.modifyQueryToBeResponse(rcode);
                state = TaskState::SEND_PACKET;
                currentBuffer = BufferType::REQUEST_BUFFER;
                currentQr = DnsMessage::QrType::RESPONSE;
                nextState = TaskState::FINISHED;

                return false;
            }

            state = TaskState::CREATE_SOCKET;

            return false;
        }

        case TaskState::CREATE_SOCKET: {
            query_socket = socket(configuration.getExternalResolvers()[currentResolver].ss_family, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);

            if (-1 == query_socket) {
                syslog(LOG_INFO, "Couldn't create socket");
                return true;
            }

            struct timeval tv {};

            tv.tv_sec = configuration.getTimeout().count() / SEC_MSEC;

            tv.tv_usec = (configuration.getTimeout().count() % SEC_MSEC) * SEC_MSEC;

            if (setsockopt(query_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
                if (query_socket > -1) {
                    close(query_socket);
                    query_socket = -1;
                }

                syslog(LOG_ERR, "Couldn't set query socket option for receive timeout %s", strerror(errno));
                return true;
            }

            if (setsockopt(query_socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
                if (query_socket > -1) {
                    close(query_socket);
                    query_socket = -1;
                }

                syslog(LOG_ERR, "Couldn't set query socket option for send timeout %s", strerror(errno));
                return true;
            }

            state = TaskState::SEND_PACKET;
            currentBuffer = BufferType::REQUEST_BUFFER;
            currentQr = DnsMessage::QrType::REQUEST;
            nextState = TaskState::PREPARE_FIRST_FORWARD;

            return false;
        }

        case TaskState::PREPARE_FIRST_FORWARD: {
            if (nullptr == ans_buffer) {
                ans_buffer = std::make_unique<uint8_t[]>(udpPayloadSize);
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

        case TaskState::SEND_PACKET: {
            if (!sendRequest(currentBuffer, currentQr)) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    syslog(LOG_ERR, "Couldn't send packet to %s, err: %s", currentQr == DnsMessage::QrType::REQUEST ? "resolver" : "client", strerror(errno));
                }

                return true;
            }

            syslog(LOG_DEBUG, "Sent packet to %s", currentQr == DnsMessage::QrType::REQUEST ? "resolver" : "client");

            state = nextState;
            dnssecState = nextDnssecState;

            return false;
        }

        case TaskState::RECEIVE_PACKET: {
            if (!receivePacket(currentBuffer)) {
                return true;
            }

            state = nextState;
            dnssecState = nextDnssecState;

            syslog(LOG_DEBUG, "Received packet from resolver");

            if (configuration.isDnssecValidated() && dnssecState == DnssecState::NON_DNSSEC) {
                dnssecState = DnssecState::DNSKEY_REQUEST;
            }

            return false;
        }

        case TaskState::FIRST_ANSWER: {
            if (dnssecState != DnssecState::NON_DNSSEC) {
                break;
            }

            DnsMessage aaaa_answer(ans_buffer.get(), answer_receive_length);

            if (aaaa_answer.getType() == DnsMessage::QrType::REQUEST) {
                syslog(LOG_WARNING, "Received a query instead of a response");
                state = TaskState::RECEIVE_PACKET;
                currentBuffer = BufferType::ANSWER_BUFFER;
                nextState = TaskState::FIRST_ANSWER;
                return false;
            }

            DnsMessage aaaa_request(req_buffer.get(), receive_length);

            auto [aaaaStart, aaaaAfterName] = aaaa_request.getRecordTypePosition(DnsMessage::SectionType::QUESTION, DnsMessage::RecordType::AAAA);

            bool hasAaaaIn = aaaaStart > 0 && aaaa_request.getClassType(aaaaAfterName + 2) == DnsMessage::ClassType::IN;

            if (!aaaa_answer.validateQuestionSection(aaaa_request)) {
                syslog(LOG_DEBUG, "Query question section does not match answer question section");
                state = TaskState::RECEIVE_PACKET;
                currentBuffer = BufferType::ANSWER_BUFFER;
                nextState = TaskState::FIRST_ANSWER;
                return false;
            }

            if (!hasAaaaIn || aaaa_answer.hasRecordType(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::AAAA)) {
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

            storeOriginalType(aaaa_request);

            /* TODO: Reuse parts from the first answer and only request A record? */
            if (!aaaa_request.setQueryType(DnsMessage::RecordType::A)) {
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

        case TaskState::A_REQUEST_SENT: {
            if (dnssecState != DnssecState::NON_DNSSEC) {
                break;
            }

            DnsMessage a_answer(ans_buffer.get(), answer_receive_length);

            if (a_answer.getType() == DnsMessage::QrType::REQUEST) {
                state = TaskState::RECEIVE_PACKET;
                currentBuffer = BufferType::ANSWER_BUFFER;
                nextState = TaskState::A_REQUEST_SENT;
                syslog(LOG_WARNING, "Received a query instead of a response");
                return false;
            }

            DnsMessage a_request(req_buffer.get(), receive_length);

            if (!a_answer.validateQuestionSection(a_request)) {
                syslog(LOG_DEBUG, "Query question section does not match answer question section");
                state = TaskState::RECEIVE_PACKET;
                currentBuffer = BufferType::ANSWER_BUFFER;
                nextState = TaskState::A_REQUEST_SENT;
                return false;
            }

            if (a_answer.hasRecordType(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::A)) {
                syslog(LOG_DEBUG, "Got A answer");

                /* TODO: Can't the request buffer be used for the forged answer? */
                if (nullptr == forged_buffer) {
                    forged_buffer = std::make_unique<uint8_t[]>(udpPayloadSize);
                }

                DnsMessage forgedMessage(forged_buffer.get(), udpPayloadSize);

                bool isSynthesized = a_answer.generateSynthetisedMessage(configuration, &forgedMessage);

                sender_length = sizeof(sockaddr_in6);

                state = TaskState::SEND_PACKET;
                currentQr = DnsMessage::QrType::RESPONSE;
                nextState = TaskState::FINISHED;

                if (isSynthesized) {
                    answer_receive_length = forgedMessage.getSize();
                    currentBuffer = BufferType::FORGED_BUFFER;
                    forgedMessage.setTransactionID(a_request.getTransactionID());
                } else {
                    a_request.modifyQueryToBeResponse(DnsMessage::ResponseCode::SERVFAIL);
                    a_request.setQueryType(DnsMessage::RecordType::AAAA);

                    answer_receive_length = receive_length;
                    currentBuffer = BufferType::REQUEST_BUFFER;
                }

                return false;
            }

            syslog(LOG_DEBUG, "Got no A answer, sending back not found");

            if (!a_answer.setQueryType(DnsMessage::RecordType::AAAA)) {
                state = TaskState::NEXT_RESOLVER;
                return false;
            }

            a_answer.setTransactionID(a_request.getTransactionID());

            state = TaskState::SEND_PACKET;
            currentBuffer = BufferType::ANSWER_BUFFER;
            currentQr = DnsMessage::QrType::RESPONSE;
            nextState = TaskState::FINISHED;

            return false;
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
        case DnssecState::DNSKEY_REQUEST: {
            DnsMessage aaaa_answer(ans_buffer.get(), answer_receive_length);

            if (aaaa_answer.getType() == DnsMessage::QrType::REQUEST) {
                syslog(LOG_WARNING, "Received a query instead of a response");
                state = TaskState::RECEIVE_PACKET;
                currentBuffer = BufferType::ANSWER_BUFFER;
                dnssecState = DnssecState::NON_DNSSEC;
                nextDnssecState = DnssecState::NON_DNSSEC;
                return false;
            }

            DnsMessage dnskey_request(req_buffer.get(), receive_length);

            if (!aaaa_answer.validateQuestionSection(dnskey_request)) {
                syslog(LOG_DEBUG, "Query question section does not match answer question section");
                state = TaskState::RECEIVE_PACKET;
                currentBuffer = BufferType::ANSWER_BUFFER;
                dnssecState = DnssecState::NON_DNSSEC;
                nextDnssecState = DnssecState::NON_DNSSEC;
                return false;
            }

            auto [rrsigStart, rrsigAfterName] = aaaa_answer.getRecordTypePosition(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::RRSIG);

            if (0 == rrsigStart) {
                syslog(LOG_DEBUG, "DNSSEC validation requested, but RRSIG not found");
                state = TaskState::RECEIVE_PACKET;
                currentBuffer = BufferType::ANSWER_BUFFER;
                dnssecState = DnssecState::NON_DNSSEC;
                nextDnssecState = DnssecState::NON_DNSSEC;
                return false;
            }

            if (!aaaa_answer.validateRrSigTimestamp(rrsigAfterName)) {
                syslog(LOG_DEBUG, "RRSIG timestamp out of range");
                state = TaskState::RECEIVE_PACKET;
                currentBuffer = BufferType::ANSWER_BUFFER;
                dnssecState = DnssecState::NON_DNSSEC;
                nextDnssecState = DnssecState::NON_DNSSEC;
                return false;
            }

            /* TODO: Signer's name VS question name */

            storeOriginalType(dnskey_request);

            auto *rrsigHeader = aaaa_answer.getRrsigHeader(rrsigAfterName);

            if (originalQueryType != static_cast<DnsMessage::RecordType>(htons(rrsigHeader->rdata.typeCovered))) {
                syslog(LOG_DEBUG, "RRSIG does not cover original type");
                state = TaskState::RECEIVE_PACKET;
                currentBuffer = BufferType::ANSWER_BUFFER;
                dnssecState = DnssecState::NON_DNSSEC;
                nextDnssecState = DnssecState::NON_DNSSEC;
                return false;
            }

            if (!resetElapsedTime()) {
                syslog(LOG_ERR, "Could not reset timer");
                return true;
            }

            if (!dnskey_request.setQueryType(DnsMessage::RecordType::DNSKEY)) {
                state = TaskState::FINISHED;
                return true;
            }

            state = TaskState::SEND_PACKET;
            currentBuffer = BufferType::REQUEST_BUFFER;
            currentQr = DnsMessage::QrType::REQUEST;
            nextDnssecState = DnssecState::PREPARE_DNSKEY;

            return false;
        }

        case DnssecState::PREPARE_DNSKEY: {

            if (nullptr == dnskey_buffer) {
                dnskey_buffer = std::make_unique<uint8_t[]>(udpPayloadSize);
            }

            state = TaskState::RECEIVE_PACKET;
            currentBuffer = BufferType::DNSKEY_BUFFER;
            nextDnssecState = DnssecState::DNSKEY_RESPONSE;

            return false;
        }

        case DnssecState::DNSKEY_RESPONSE: {
            DnsMessage dnskey_request(req_buffer.get(), receive_length);

            DnsMessage aaaa_answer(ans_buffer.get(), answer_receive_length);

            auto [rrsigStart, rrsigAfterName] = aaaa_answer.getRecordTypePosition(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::RRSIG);

            DnsMessage dnskey_answer(dnskey_buffer.get(), dnskey_receive_length);

            if (dnskey_answer.getType() == DnsMessage::QrType::REQUEST) {
                state = TaskState::RECEIVE_PACKET;
                currentBuffer = BufferType::DNSKEY_BUFFER;
                nextDnssecState = DnssecState::DNSKEY_RESPONSE;
                syslog(LOG_WARNING, "Received a query instead of a response");
                return false;
            }

            if (!dnskey_answer.validateQuestionSection(dnskey_request)) {
                state = TaskState::RECEIVE_PACKET;
                currentBuffer = BufferType::DNSKEY_BUFFER;
                nextDnssecState = DnssecState::DNSKEY_RESPONSE;
                syslog(LOG_DEBUG, "Query question section does not match answer question section");
                return false;
            }

            if (!dnskey_answer.hasRecordType(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::DNSKEY)) {
                state = TaskState::RECEIVE_PACKET;
                currentBuffer = BufferType::DNSKEY_BUFFER;
                nextDnssecState = DnssecState::DNSKEY_RESPONSE;
                syslog(LOG_DEBUG, "DNSSEC validation requested, but DNSKEY not found");
                return false;
            }

            syslog(LOG_DEBUG, "Got DNSKEY answer");

            auto *rrsigHeader = aaaa_answer.getRrsigHeader(rrsigAfterName);

            uint16_t dnsKeyPosition = 0;

            while (true) {
                auto [dnsKeyStart, dnsKeyAfterName] = dnskey_answer.getRecordTypePosition(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::DNSKEY, dnsKeyPosition);

                dnsKeyPosition = dnsKeyStart;

                if (0 == dnsKeyPosition) {
                    state = TaskState::RECEIVE_PACKET;
                    currentBuffer = BufferType::DNSKEY_BUFFER;
                    nextDnssecState = DnssecState::DNSKEY_RESPONSE;
                    syslog(LOG_DEBUG, "Could not find matching DNSKEY");
                    return false;
                }

                auto *dnsKeyHeader = dnskey_answer.getDnsKeyHeader(dnsKeyAfterName);

                /* DNSKEY has to be a zone key to be used for validation */
                if (!dnsKeyHeader->isZoneKey) {
                    syslog(LOG_DEBUG, "DNSKEY is not a zone key");
                    continue;
                }

                if (dnsKeyHeader->algorithm != rrsigHeader->rdata.algorithm) {
                    syslog(LOG_DEBUG, "The algorithms of DNSKEY and RRSIG do not match");
                    continue;
                }

                auto keyTag = dnskey_answer.calculateKeyTag(dnsKeyAfterName);

                if (keyTag != htons(rrsigHeader->rdata.keyTag)) {
                    syslog(LOG_DEBUG, "The key tags of DNSKEY and RRSIG do not match");
                    continue;
                }

                syslog(LOG_DEBUG, "DNSKEY and RRSIG match, keytag: %u, algo: %u", keyTag, dnsKeyHeader->algorithm);

                auto [recordStart, recordAfterName] = aaaa_answer.getRecordTypePosition(DnsMessage::SectionType::ANSWER, originalQueryType);

                auto *rrHeader = aaaa_answer.getRrHeader(recordAfterName);

                size_t bufferPosition = 0;

                uint16_t signerNameEnd = aaaa_answer.getNamePosition(rrsigAfterName + DnsMessage::LEN_RRSIG_FIXED);

                uint16_t signerNameLength = signerNameEnd - rrsigAfterName - DnsMessage::LEN_RRSIG_FIXED;

                auto signatureBuffer = std::make_unique<uint8_t[]>(DnsMessage::MAX_LEN_SIG_BUFFER);

                /* RRSIG RDATA - Signature */
                memcpy(signatureBuffer.get(), &rrsigHeader->rdata.typeCovered, signerNameLength + DnsMessage::LEN_RRSIG_RDATA_FIXED);

                bufferPosition += signerNameLength + DnsMessage::LEN_RRSIG_RDATA_FIXED;

                // EXPERIMENTAL

                /* RRSIG signer name as RR owner name */
                memcpy(signatureBuffer.get() + bufferPosition, &aaaa_answer.getBuffer()[rrsigAfterName + DnsMessage::LEN_RRSIG_FIXED], signerNameLength);

                bufferPosition += signerNameLength;

                /* RR TYPE, CLASS */
                memcpy(signatureBuffer.get() + bufferPosition, &aaaa_answer.getBuffer()[recordAfterName], 4);

                bufferPosition += 4;

                // EXPERIMENTAL

                //memcpy(signatureBuffer.get() + bufferPosition, &aaaa_answer.getBuffer().get()[recordStart], recordAfterName - recordStart + 4);

                //bufferPosition += recordAfterName - recordStart + 4;

                /* RRSIG TTL --> RR TTL */
                memcpy(signatureBuffer.get() + bufferPosition, &rrsigHeader->rdata.originalTtl, 4);

                bufferPosition += 4;

                uint16_t rrHeaderLength = htons(rrHeader->rdlength);

                /* RR RDLENGTH + RDATA */
                memcpy(signatureBuffer.get() + bufferPosition, &rrHeader->rdlength, 2 + rrHeaderLength);

                bufferPosition += 2 + rrHeaderLength;

                const uint8_t* signatureStart = &dnsKeyHeader->algorithm + 1;

                RSA *pubKey = RSA_new();

                if (nullptr == pubKey) {
                    syslog(LOG_DEBUG, "Could not allocate RSA key structure");
                    continue;
                }

                size_t expLength = signatureStart[0];

                BIGNUM *e = BN_bin2bn(&signatureStart[1], expLength, nullptr);

                BIGNUM *n = BN_bin2bn(&signatureStart[1 + expLength], htons(dnsKeyHeader->header.rdlength) - 4U - expLength - 1U, nullptr);

                if (0 == RSA_set0_key(pubKey, n, e, nullptr)) {
                    syslog(LOG_DEBUG, "Could not set RSA key values");
                    RSA_free(pubKey);
                    continue;
                }

                std::array<unsigned char, SHA256_DIGEST_LENGTH> hash{};

                SHA256_CTX sha256;
                SHA256_Init(&sha256);
                SHA256_Update(&sha256, signatureBuffer.get(), bufferPosition);
                SHA256_Final(hash.data(), &sha256);

                if (1 == RSA_verify(NID_sha256, hash.data(), SHA256_DIGEST_LENGTH, &aaaa_answer.getBuffer()[signerNameEnd],
                                    htons(rrsigHeader->header.rdlength) - signerNameLength - DnsMessage::LEN_RRSIG_RDATA_FIXED, pubKey)) {
                    syslog(LOG_DEBUG, "RSA validation successful");
                    RSA_free(pubKey);

                    if (!resetElapsedTime()) {
                        syslog(LOG_ERR, "Could not reset timer");
                        return true;
                    }

                    dnssecState = DnssecState::DS_REQUEST;
                    return false;
                }

                unsigned long err = 0;

                while ((err = ERR_get_error()) != 0) {
                    /* This is not an error condition, checking next key */
                    syslog(LOG_DEBUG, "RSA validation has failed: %s", ERR_error_string(err, nullptr));
                }

                RSA_free(pubKey);
            }
        }

        case DnssecState::DS_REQUEST: {
            DnsMessage dnskey_request(req_buffer.get(), receive_length);

            storeOriginalType(dnskey_request);

            if (!dnskey_request.setQueryType(DnsMessage::RecordType::DS)) {
                syslog(LOG_ERR, "Couldn't set query to DS");
                state = TaskState::FINISHED;
                return true;
            }

            state = TaskState::SEND_PACKET;
            currentBuffer = BufferType::REQUEST_BUFFER;
            currentQr = DnsMessage::QrType::REQUEST;
            nextDnssecState = DnssecState::PREPARE_DS;

            return false;
        }

        case DnssecState::PREPARE_DS: {
            if (nullptr == ds_buffer) {
                ds_buffer = std::make_unique<uint8_t[]>(udpPayloadSize);
            }

            state = TaskState::RECEIVE_PACKET;
            currentBuffer = BufferType::DS_BUFFER;
            nextDnssecState = DnssecState::DS_RESPONSE;

            return false;
        }

        case DnssecState::DS_RESPONSE: {
            DnsMessage ds_answer(ds_buffer.get(), ds_receive_length);

            if (ds_answer.getType() == DnsMessage::QrType::REQUEST) {
                state = TaskState::RECEIVE_PACKET;
                currentBuffer = BufferType::DS_BUFFER;
                nextDnssecState = DnssecState::DS_RESPONSE;
                syslog(LOG_WARNING, "Received a query instead of a response");
                return false;
            }

            DnsMessage dnskey_request(req_buffer.get(), receive_length);

            if (!ds_answer.validateQuestionSection(dnskey_request)) {
                state = TaskState::RECEIVE_PACKET;
                currentBuffer = BufferType::DS_BUFFER;
                nextDnssecState = DnssecState::DS_RESPONSE;
                syslog(LOG_DEBUG, "Query question section does not match answer question section");
                return false;
            }

            if (!ds_answer.hasRecordType(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::DS)) {
                state = TaskState::RECEIVE_PACKET;
                currentBuffer = BufferType::DS_BUFFER;
                nextDnssecState = DnssecState::DS_RESPONSE;
                syslog(LOG_DEBUG, "DNSSEC validation requested, but DS not found");
                return false;
            }

            if (!resetElapsedTime()) {
                syslog(LOG_ERR, "Could not reset timer");
                return true;
            }

            syslog(LOG_DEBUG, "Got DS answer");

            dnskey_request.setQueryType(originalQueryType);

            dnssecState = DnssecState::NON_DNSSEC;
            nextDnssecState = DnssecState::NON_DNSSEC;

            return false;
        }

        default:
            /* Unknown state results in an exit from the loop */
            state = TaskState::FINISHED;
            return true;
    }
}

void Task::handleStateWrapper() {
    while (!handleState()) {};
}

auto Task::getBufferByType(BufferType type) -> uint8_t * {
    switch(type) {
        case BufferType::REQUEST_BUFFER:
            return req_buffer.get();

        case BufferType::ANSWER_BUFFER:
            return ans_buffer.get();

        case BufferType::DNSKEY_BUFFER:
            return dnskey_buffer.get();

        case BufferType::DS_BUFFER:
            return ds_buffer.get();

        case BufferType::FORGED_BUFFER:
            return forged_buffer.get();
    }

    return nullptr;
}

auto Task::receivePacket(BufferType type) -> bool {
    int count{};
    ioctl(query_socket, FIONREAD, &count);

    if (count == 0) {
        return false;
    }

    uint8_t *buffer = getBufferByType(type);

    if (nullptr == buffer) {
        syslog(LOG_DEBUG, "Couldn't get buffer by type during receive");
        state = TaskState::NEXT_RESOLVER;
        return false;
    }

    ssize_t temp_receive_length = recv(query_socket, buffer, udpPayloadSize, 0);

    if (DnsMessage::DNS_HEADER_LENGTH > temp_receive_length) {
        if (0 < temp_receive_length) {
            return false; /* Packet with invalid header, waiting for another one */
        }

        syslog(LOG_ERR, "Couldn't receive query from resolver, err: %s", strerror(errno));
        state = TaskState::NEXT_RESOLVER;
        return false;
    }

    switch(type) {
        case BufferType::DNSKEY_BUFFER:
            dnskey_receive_length = temp_receive_length;
            return true;

        case BufferType::DS_BUFFER:
            ds_receive_length = temp_receive_length;
            return true;

        case BufferType::ANSWER_BUFFER:
            answer_receive_length = temp_receive_length;
            return true;

        default:
            syslog(LOG_ERR, "Unknown buffer type when receiving packet");
            state = TaskState::NEXT_RESOLVER;
            return false;
    }
}

auto Task::sendRequest(BufferType type, DnsMessage::QrType qrType) -> bool {
    uint8_t *buffer = getBufferByType(type);

    int socket;
    const sockaddr *address;
    socklen_t address_size;
    size_t whole_length;

    if (DnsMessage::QrType::REQUEST == qrType) {
        const auto &resolver = configuration.getExternalResolvers()[currentResolver];

        socket = query_socket;
        address = reinterpret_cast<const sockaddr *>(&resolver);
        address_size = sizeof(resolver);
        whole_length = receive_length;
    } else {
        socket = receiver_socket;
        address = reinterpret_cast<const sockaddr *>(&sender);
        address_size = sender_length;

        switch(type) {
            case BufferType::REQUEST_BUFFER:
                whole_length = receive_length;
                break;

            case BufferType::ANSWER_BUFFER:
                whole_length = answer_receive_length;
                break;

            case BufferType::FORGED_BUFFER:
                whole_length = answer_receive_length;
                break;

            case BufferType::DNSKEY_BUFFER:
                whole_length = dnskey_receive_length;
                break;

            case BufferType::DS_BUFFER:
                whole_length = ds_receive_length;
                break;
        }
    }

    if (nullptr == buffer) {
        return false; /* Avoiding double error message */
    }

    /* TODO: Send the A and the AAAA query concurrently */
    size_t all_sent_bytes = 0;
    ssize_t current_sent_bytes = 0;

    while (all_sent_bytes < whole_length) {
        current_sent_bytes = sendto(socket, &buffer[all_sent_bytes], whole_length - all_sent_bytes, 0, address, address_size);

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

            case DnssecState::DS_REQUEST:
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