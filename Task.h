#pragma once

#include "Configuration.h"
#include "DnsMessage.h"

#include <array>
#include <chrono>
#include <memory>
#include <netinet/in.h>
#include <unistd.h>
#include <vector>
#include <iostream>
#include <syslog.h>

/* TODO: State when cannot start communication due to socket exhaustion */
enum class TaskState {
    INITIAL,
    INITIAL_RESPONSE,
    NON_AAAA_QUERY,
    AAAA_REQUEST_SENT,
    A_REQUEST_SENT,
    NEXT_RESOLVER,
    FINISHED
};

enum class DnssecState {
    NON_DNSSEC,
    DNSKEY_REQUEST,
    DNSKEY_RESPONSE,
    DS_REQUEST,
    DS_RESPONSE,
    VALIDATED
};

enum class BufferType {
    REQUEST_BUFFER,
    ANSWER_BUFFER,
    DNSKEY_BUFFER,
    DS_BUFFER,
    FORGED_BUFFER
};

class Task {
        std::chrono::steady_clock::time_point start_time;
        const Configuration &configuration;
        uint16_t processor;
        int receiver_socket{};
        int query_socket{-1};
        std::unique_ptr<uint8_t> req_buffer;
        std::unique_ptr<uint8_t> ans_buffer;
        std::unique_ptr<uint8_t> dnskey_buffer;
        std::unique_ptr<uint8_t> ds_buffer;
        std::unique_ptr<uint8_t> forged_buffer;
        struct sockaddr_in6 sender{};
        socklen_t sender_length{};
        ssize_t receive_length{};
        ssize_t answer_receive_length{};
        TaskState state{TaskState::INITIAL};
        DnssecState dnssecState{DnssecState::NON_DNSSEC};
        uint16_t udpPayloadSize{0};
        uint16_t currentResolver{0};
        uint16_t attempt{0};
        DnsMessage::RecordType originalQueryType{DnsMessage::RecordType::NO_VALUE};
    public:
        Task(const Configuration &configuration, int receiver_socket, std::unique_ptr<uint8_t> buffer, struct sockaddr_in6 sender, socklen_t sender_length, ssize_t receive_length) :
            configuration(configuration), receiver_socket(receiver_socket), req_buffer(std::move(buffer)), sender(sender), sender_length(sender_length), receive_length(receive_length),
            udpPayloadSize(configuration.getUdpPayloadSize()) {
            start_time = std::chrono::steady_clock::now();
            syslog(LOG_DEBUG, "Task executing on processor %u", processor);
        }
        Task(const Task&) = delete;
        auto operator=(const Task&) -> Task& = delete;

        auto getElapsedTime() const -> int64_t {
            auto current_time = std::chrono::steady_clock::now();
            return std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time).count();
        }

        auto resetElapsedTime() -> void {
            start_time = std::chrono::steady_clock::now();
        }

        void setProcessor(uint16_t processor) {
            this->processor = processor;
        }

        bool parseResponse();
        bool stateHandler();

        [[nodiscard]] auto getState() const -> TaskState {
            return state;
        }

        void printState();

        void storeOriginalType(DnsMessage &query) {
            if (originalQueryType != DnsMessage::RecordType::NO_VALUE) {
                return;
            }

            query.getQueryType(originalQueryType);
        }

        bool receivePacket(BufferType type, ssize_t &receive_length);

        uint8_t *getBufferByType(BufferType type);

        bool sendRequest(BufferType type, DnsMessage::QrType qrType);

        ~Task() {
            if (query_socket > -1) {
                close(query_socket);
            }
        }
};