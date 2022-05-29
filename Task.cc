#include "Task.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <sys/ioctl.h>
#include <syslog.h>

/* TODO: Implement random-access of resolvers (round-robin makes no sense as it would require thread syncing)
         Random-access has to be linear */
bool Task::stateHandler() {
    if (dnssecState != DnssecState::NON_DNSSEC && dnssecState != DnssecState::VALIDATED) {
        if (state == TaskState::INITIAL || state == TaskState::NEXT_RESOLVER) {
            dnssecState = DnssecState::NON_DNSSEC;
            return true;
        }

        if (dnssecState == DnssecState::DNSKEY_REQUEST) {
            DnsMessage aaaa_answer(ans_buffer, configuration, answer_receive_length);

            if (aaaa_answer.getType() == DnsMessage::QrType::REQUEST) {
                syslog(LOG_WARNING, "Received a query instead of a response");
                return true;
            }

            DnsMessage dnskey_request(req_buffer, configuration, receive_length);

            if (!aaaa_answer.validateQuestionSection(dnskey_request)) {
                syslog(LOG_DEBUG, "Query question section does not match answer question section");
                state = TaskState::NEXT_RESOLVER;
                return true;
            }
            
            auto [rrsigStart, rrsigAfterName] = aaaa_answer.getRecordTypePosition(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::RRSIG);

            if (0 == rrsigStart) {
                syslog(LOG_DEBUG, "DNSSEC validation requested, but RRSIG not found");
                state = TaskState::NEXT_RESOLVER;
                return true;
            }

            if (!aaaa_answer.validateRrSigTimestamp(rrsigAfterName)) {
                syslog(LOG_DEBUG, "RRSIG timestamp out of range");
                state = TaskState::NEXT_RESOLVER;
                return true;
            }

            /* TODO: Signer's name VS question name */

            storeOriginalType(dnskey_request);

            auto rrsigHeader = aaaa_answer.getRrsigHeader(rrsigAfterName);

            if (originalQueryType != static_cast<DnsMessage::RecordType>(htons(rrsigHeader->rdata.typeCovered))) {
                syslog(LOG_DEBUG, "RRSIG does not cover original type");
                state = TaskState::NEXT_RESOLVER;
                return true;
            }

            if (!dnskey_request.setQueryType(DnsMessage::RecordType::DNSKEY)) {
                return false;
            }

            if (!sendRequest(BufferType::REQUEST_BUFFER, DnsMessage::QrType::REQUEST)) {
                syslog(LOG_ERR, "Couldn't send query to resolver, err: %s", strerror(errno));
                state = TaskState::NEXT_RESOLVER;
                return false;
            }

            syslog(LOG_DEBUG, "Sent DNSKEY query");

            dnskey_buffer.reset(new uint8_t[udpPayloadSize]);

            dnssecState = DnssecState::DNSKEY_RESPONSE;
        } else if (dnssecState == DnssecState::DNSKEY_RESPONSE) {
            ssize_t dnskey_receive_length{};

            if (!receivePacket(BufferType::DNSKEY_BUFFER, dnskey_receive_length)) {
                return true;
            }

            DnsMessage dnskey_request(req_buffer, configuration, receive_length);

            DnsMessage aaaa_answer(ans_buffer, configuration, answer_receive_length);
            
            auto [rrsigStart, rrsigAfterName] = aaaa_answer.getRecordTypePosition(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::RRSIG);

            DnsMessage dnskey_answer(dnskey_buffer, configuration, dnskey_receive_length);

            if (dnskey_answer.getType() == DnsMessage::QrType::REQUEST) {
                syslog(LOG_WARNING, "Received a query instead of a response");
                return true;
            }

            if (!dnskey_answer.validateQuestionSection(dnskey_request)) {
                syslog(LOG_DEBUG, "Query question section does not match answer question section");
                state = TaskState::NEXT_RESOLVER;
                return true;
            }

            if (!dnskey_answer.hasRecordType(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::DNSKEY)) {
                syslog(LOG_DEBUG, "DNSSEC validation requested, but DNSKEY not found");
                state = TaskState::NEXT_RESOLVER;
                return true;
            }

            syslog(LOG_DEBUG, "Got DNSKEY answer");

            auto rrsigHeader = aaaa_answer.getRrsigHeader(rrsigAfterName);

            uint16_t dnsKeyPosition = 0;

            while (true) {
                auto [dnsKeyStart, dnsKeyAfterName] = dnskey_answer.getRecordTypePosition(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::DNSKEY, dnsKeyPosition);

                dnsKeyPosition = dnsKeyStart;

                if (0 == dnsKeyPosition) {
                    syslog(LOG_DEBUG, "Could not find matching DNSKEY");
                    state = TaskState::NEXT_RESOLVER;
                    return true;
                }

                auto dnsKeyHeader = dnskey_answer.getDnsKeyHeader(dnsKeyAfterName);

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

                auto [recordStart, recordAfterName] = aaaa_answer.getRecordTypePosition(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::A);

                auto rrHeader = aaaa_answer.getRrHeader(recordAfterName);

                size_t bufferPosition = 0;

                uint16_t signerNameEnd = aaaa_answer.getNamePosition(rrsigAfterName + 28U);

                uint16_t signerNameLength = signerNameEnd - rrsigAfterName - 28U;

                std::unique_ptr<uint8_t> signatureBuffer(new uint8_t[8192]);

                /* RRSIG RDATA - Signature */
                memcpy(signatureBuffer.get(), &rrsigHeader->rdata.typeCovered, signerNameLength + 18U);

                bufferPosition += signerNameLength + 18U;

                // EXPERIMENTAL

                /* RRSIG signer name as RR owner name */
                memcpy(signatureBuffer.get() + bufferPosition, &aaaa_answer.getBuffer().get()[rrsigAfterName + 28U], signerNameLength);

                bufferPosition += signerNameLength;

                /* RR TYPE, CLASS */
                memcpy(signatureBuffer.get() + bufferPosition, &aaaa_answer.getBuffer().get()[recordAfterName], 4);

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

                BIGNUM *e = BN_bin2bn(&signatureStart[1], expLength, NULL);

                BIGNUM *n = BN_bin2bn(&signatureStart[1 + expLength], htons(dnsKeyHeader->header.rdlength) - 4U - expLength - 1U, NULL);

                if (0 == RSA_set0_key(pubKey, n, e, NULL)) {
                    syslog(LOG_DEBUG, "Could not set RSA key values");
                    RSA_free(pubKey);
                    continue;
                }

                unsigned char hash[SHA256_DIGEST_LENGTH];
                SHA256_CTX sha256;
                SHA256_Init(&sha256);
                SHA256_Update(&sha256, signatureBuffer.get(), bufferPosition);
                SHA256_Final(hash, &sha256);

                if (1 == RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, &aaaa_answer.getBuffer().get()[signerNameEnd],
                                    htons(rrsigHeader->header.rdlength) - signerNameLength - 18U, pubKey)) {
                    syslog(LOG_DEBUG, "RSA validation successful");
                    RSA_free(pubKey);
                    dnssecState = DnssecState::DS_REQUEST;
                    return true;
                }

                unsigned long err = 0;

                while ((err = ERR_get_error()) != 0) {
                    /* This is not an error condition, checking next key */
                    syslog(LOG_DEBUG, "RSA validation has failed: %s", ERR_error_string(err, NULL));
                }

                RSA_free(pubKey);
            }
        } else if (dnssecState == DnssecState::DS_REQUEST) {
            DnsMessage dnskey_request(req_buffer, configuration, receive_length);

            storeOriginalType(dnskey_request);

            if (!dnskey_request.setQueryType(DnsMessage::RecordType::DS)) {
                syslog(LOG_ERR, "Couldn't set query to DS");
                state = TaskState::NEXT_RESOLVER;
                return false;
            }

            if (!sendRequest(BufferType::REQUEST_BUFFER, DnsMessage::QrType::REQUEST)) {
                syslog(LOG_ERR, "Couldn't send query to resolver, err: %s", strerror(errno));
                state = TaskState::NEXT_RESOLVER;
                return false;
            }

            syslog(LOG_DEBUG, "Sent DS query");

            ds_buffer.reset(new uint8_t[udpPayloadSize]);

            dnssecState = DnssecState::DS_RESPONSE;
        } else if (dnssecState == DnssecState::DS_RESPONSE) {
            ssize_t ds_receive_length{};

            if (!receivePacket(BufferType::DS_BUFFER, ds_receive_length)) {
                return true;
            }

            DnsMessage ds_answer(ds_buffer, configuration, ds_receive_length);

            if (ds_answer.getType() == DnsMessage::QrType::REQUEST) {
                syslog(LOG_WARNING, "Received a query instead of a response");
                return true;
            }

            DnsMessage dnskey_request(req_buffer, configuration, receive_length);

            if (!ds_answer.validateQuestionSection(dnskey_request)) {
                syslog(LOG_DEBUG, "Query question section does not match answer question section");
                state = TaskState::NEXT_RESOLVER;
                return true;
            }

            if (!ds_answer.hasRecordType(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::DS)) {
                syslog(LOG_DEBUG, "DNSSEC validation requested, but DS not found");
                state = TaskState::NEXT_RESOLVER;
                return true;
            }

            syslog(LOG_DEBUG, "Got DS answer");

            dnskey_request.setQueryType(originalQueryType);

            dnssecState = DnssecState::VALIDATED;
        }

        return true;
    }

    if (state == TaskState::INITIAL) {
        DnsMessage aaaa_request(req_buffer, configuration, receive_length);

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
            state = TaskState::INITIAL_RESPONSE;

            return true;
        }

        if (!aaaa_request.isOpCodeValid()) {
            aaaa_request.modifyQueryToBeResponse(DnsMessage::ResponseCode::NOTIMP);
            state = TaskState::INITIAL_RESPONSE;

            return true;
        }

        DnsMessage::ResponseCode rcode = DnsMessage::ResponseCode::NOERROR;

        udpPayloadSize = aaaa_request.updateUdpPayloadSize(rcode);

        if (0 == udpPayloadSize) {
            aaaa_request.modifyQueryToBeResponse(rcode);
            state = TaskState::INITIAL_RESPONSE;

            return true;
        }

        /** TODO: Keep socket open? */
        query_socket = socket(configuration.getExternalResolvers()[currentResolver].ss_family, SOCK_DGRAM, IPPROTO_UDP);

        if (-1 == query_socket) {
            syslog(LOG_ERR, "Couldn't create socket on processor %u", processor);
            return false;
        }
        
        if (fcntl(query_socket, F_SETFL, O_NONBLOCK) == -1) {
            if (query_socket > -1) {
                close(query_socket);
                query_socket = -1;
            }

            return false;
        }

        if (!sendRequest(BufferType::REQUEST_BUFFER, DnsMessage::QrType::REQUEST)) {
            syslog(LOG_ERR, "Couldn't send query to resolver, err: %s", strerror(errno));
            state = TaskState::NEXT_RESOLVER;
            return false;
        }

        auto [aaaaStart, aaaaAfterName] = aaaa_request.getRecordTypePosition(DnsMessage::SectionType::QUESTION, DnsMessage::RecordType::AAAA);

        if (aaaaStart > 0 && aaaa_request.getClassType(aaaaAfterName + 2) == DnsMessage::ClassType::IN) {
            state = TaskState::AAAA_REQUEST_SENT;
        } else {
            state = TaskState::NON_AAAA_QUERY;
        }

        ans_buffer.reset(new uint8_t[udpPayloadSize]);

        return true;
    }

    if (state == TaskState::INITIAL_RESPONSE) {
        answer_receive_length = receive_length;

        if (!sendRequest(BufferType::REQUEST_BUFFER, DnsMessage::QrType::RESPONSE)) {
            syslog(LOG_ERR, "Couldn't send error to client, err: %s", strerror(errno));
            return false;
        }
        
        syslog(LOG_DEBUG, "Sent error message");

        state = TaskState::FINISHED;
    }

    if (state == TaskState::AAAA_REQUEST_SENT || state == TaskState::NON_AAAA_QUERY) {
        if (dnssecState != DnssecState::VALIDATED) {
            if (!receivePacket(BufferType::ANSWER_BUFFER, answer_receive_length)) {
                return true;
            }
        }

        if (configuration.isDnssecValidated() && dnssecState != DnssecState::VALIDATED) {
            dnssecState = DnssecState::DNSKEY_REQUEST;

            return true;
        }

        DnsMessage aaaa_answer(ans_buffer, configuration, answer_receive_length);

        if (aaaa_answer.getType() == DnsMessage::QrType::REQUEST) {
            syslog(LOG_WARNING, "Received a query instead of a response");
            return true;
        }

        DnsMessage aaaa_request(req_buffer, configuration, receive_length);

        if (!aaaa_answer.validateQuestionSection(aaaa_request)) {
            syslog(LOG_DEBUG, "Query question section does not match answer question section");
            state = TaskState::NEXT_RESOLVER;
            return true;
        }

        if (state == TaskState::NON_AAAA_QUERY || aaaa_answer.hasRecordType(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::AAAA)) {
            if (state == TaskState::NON_AAAA_QUERY) {
                syslog(LOG_DEBUG, "Got non-AAAA answer");
            } else {
                syslog(LOG_DEBUG, "Got AAAA answer");
            }

            if (!sendRequest(BufferType::ANSWER_BUFFER, DnsMessage::QrType::RESPONSE)) {
                syslog(LOG_ERR, "Couldn't send answer to client, err: %s", strerror(errno));
                return false;
            }

            state = TaskState::FINISHED;
        } else {
            DnsMessage a_request(req_buffer, configuration, receive_length);

            storeOriginalType(a_request);

            /* TODO: Reuse parts from the first answer and only request A record? */
            if (!a_request.setQueryType(DnsMessage::RecordType::A)) {
                syslog(LOG_ERR, "Couldn't set query to A");
                state = TaskState::NEXT_RESOLVER;
                return false;
            }

            if (!sendRequest(BufferType::REQUEST_BUFFER, DnsMessage::QrType::REQUEST)) {
                syslog(LOG_ERR, "Couldn't send query to resolver, err: %s", strerror(errno));
                state = TaskState::NEXT_RESOLVER;
                return false;
            }

            state = TaskState::A_REQUEST_SENT;
        }

        return true;
    }

    if (state == TaskState::A_REQUEST_SENT) {
        if (!receivePacket(BufferType::ANSWER_BUFFER, answer_receive_length)) {
            return true;
        }

        DnsMessage a_answer(ans_buffer, configuration, answer_receive_length);

        DnsMessage a_request(req_buffer, configuration, receive_length);

        if (a_answer.getType() == DnsMessage::QrType::REQUEST) {
            syslog(LOG_WARNING, "Received a query instead of a response");
            return true;
        }

        if (!a_answer.validateQuestionSection(a_request)) {
            syslog(LOG_DEBUG, "Query question section does not match answer question section");
            state = TaskState::NEXT_RESOLVER;
            return true;
        }

        if (a_answer.hasRecordType(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::A) > 0) {
            syslog(LOG_DEBUG, "Got A answer");

            /* TODO: Can't the request buffer be used for the forged answer? */
            forged_buffer.reset(new uint8_t[udpPayloadSize]);
            DnsMessage synthesized = a_answer.generateSynthetisedMessage(forged_buffer, udpPayloadSize, configuration.getPrefix());

            DnsMessage a_request(req_buffer, configuration, receive_length);
            synthesized.setTransactionID(a_request.getTransactionID());

            sender_length = sizeof(sockaddr_in6);

            bool sendResult;

            if (synthesized.isValid()) {
                answer_receive_length = synthesized.getSize();
                sendResult = sendRequest(BufferType::FORGED_BUFFER, DnsMessage::QrType::RESPONSE);
            } else {
                a_request.modifyQueryToBeResponse(DnsMessage::ResponseCode::SERVFAIL);
                a_request.setQueryType(DnsMessage::RecordType::AAAA);
                answer_receive_length = receive_length;                
                sendResult = sendRequest(BufferType::REQUEST_BUFFER, DnsMessage::QrType::RESPONSE);
            }

            if (!sendResult) {
                syslog(LOG_ERR, "Couldn't send answer to client, err: %s", strerror(errno));
                return false;
            }
            
            syslog(LOG_DEBUG, "Sent AAAA answer");

            state = TaskState::FINISHED;
        } else {
            syslog(LOG_DEBUG, "Got no A answer, sending back not found");

            if (!a_answer.setQueryType(DnsMessage::RecordType::AAAA)) {
                return false;
            }

            DnsMessage a_request(req_buffer, configuration, receive_length);
            a_answer.setTransactionID(a_request.getTransactionID());

            if (!sendRequest(BufferType::ANSWER_BUFFER, DnsMessage::QrType::RESPONSE)) {
                syslog(LOG_ERR, "Couldn't send answer to client, err: %s", strerror(errno));
                return false;
            }
            
            syslog(LOG_DEBUG, "Sent not found");

            state = TaskState::FINISHED;
        }
    }

    if (state == TaskState::NEXT_RESOLVER) {
        attempt++;

        if (attempt < configuration.getAttempts()) {
            if (originalQueryType != DnsMessage::RecordType::NO_VALUE) {
                DnsMessage dns_request(req_buffer, configuration, receive_length);

                dns_request.setQueryType(originalQueryType);

                originalQueryType = DnsMessage::RecordType::NO_VALUE;
            }

            state = TaskState::INITIAL;
            dnssecState = DnssecState::NON_DNSSEC;

            if (query_socket > -1) {
                close(query_socket);
                query_socket = -1;
            }

            return true;
        }

        attempt = 0;

        if (currentResolver < static_cast<uint16_t>(UINT16_MAX)) {
            currentResolver++;
        }

        if (currentResolver >= configuration.getExternalResolvers().size()) {
            state = TaskState::FINISHED;
            dnssecState = DnssecState::NON_DNSSEC;
            return true;
        }

        syslog(LOG_DEBUG, "Attempting the request with the next resolver");
        state = TaskState::INITIAL;
        dnssecState = DnssecState::NON_DNSSEC;

        if (query_socket > -1) {
            close(query_socket);
            query_socket = -1;
        }

        if (originalQueryType != DnsMessage::RecordType::NO_VALUE) {
            DnsMessage dns_request(req_buffer, configuration, receive_length);

            dns_request.setQueryType(originalQueryType);

            originalQueryType = DnsMessage::RecordType::NO_VALUE;
        }

        return true;
    }

    return true;
}

uint8_t *Task::getBufferByType(BufferType type) {
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

bool Task::receivePacket(BufferType type, ssize_t &receive_length) {
    int count{};
    ioctl(query_socket, FIONREAD, &count);

    if (count == 0) {
        if (getElapsedTime() > configuration.getTimeout()) {
            syslog(LOG_DEBUG, "Timeout occured when listening for response");
            state = TaskState::NEXT_RESOLVER;
        }

        return false;
    }

    uint8_t *buffer = getBufferByType(type);

    if (nullptr == buffer) {
        syslog(LOG_DEBUG, "Couldn't get buffer by type during receive");
        state = TaskState::NEXT_RESOLVER;
        return false;
    }

    ssize_t temp_receive_length = recv(query_socket, buffer, udpPayloadSize, 0);

    if (DNS_HEADER_LENGTH > temp_receive_length) {
        syslog(LOG_ERR, "Couldn't receive query from resolver, err: %s", strerror(errno));;
        state = TaskState::NEXT_RESOLVER;
        return false;
    }

    resetElapsedTime();

    receive_length = temp_receive_length;

    return true;
}

bool Task::sendRequest(BufferType type, DnsMessage::QrType qrType) {
    uint8_t *buffer = getBufferByType(type);

    int socket;
    const sockaddr *address;
    socklen_t address_size;
    size_t whole_length;

    if (DnsMessage::QrType::REQUEST == qrType) {
        auto &resolver = configuration.getExternalResolvers()[currentResolver];

        socket = query_socket;
        address = reinterpret_cast<const sockaddr *>(&resolver);
        address_size = sizeof(resolver);
        whole_length = receive_length;
    } else {
        socket = receiver_socket;
        address = reinterpret_cast<const sockaddr *>(&sender);
        address_size = sender_length;
        whole_length = answer_receive_length;
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
    switch(state) {
        case TaskState::INITIAL:
            syslog(LOG_DEBUG, "Initial");
            return;
        case TaskState::INITIAL_RESPONSE:
            syslog(LOG_DEBUG, "Initial response");
            return;
        case TaskState::NON_AAAA_QUERY:
            syslog(LOG_DEBUG, "Got non-AAAA query");
            return;
        case TaskState::A_REQUEST_SENT:
            syslog(LOG_DEBUG, "A request sent");
            return;
        case TaskState::AAAA_REQUEST_SENT:
            syslog(LOG_DEBUG, "AAAA request sent");
            return;
        case TaskState::NEXT_RESOLVER:
            syslog(LOG_DEBUG, "Next resolver");
            return;
        case TaskState::FINISHED:
            syslog(LOG_DEBUG, "Finished");
            return;
    }
}