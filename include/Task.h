/**
 * @file Task.h
 * @author Andras Attila Gerendas
 * @brief Class containing the state machine for DNS packet processing
 * @version 0.1
 * @date 2022-06-21
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef DNS64SEC_TASK_H
#define DNS64SEC_TASK_H

#include "Configuration.h"
#include "DnsMessage.h"

#include <array>
#include <chrono>
#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <queue>
#include <sys/timerfd.h>
#include <syslog.h>
#include <unistd.h>
#include <vector>

/* TODO: State when cannot start communication due to socket exhaustion */
/**
 * @brief The primary state of the current task
 *
 */
enum class TaskState : uint8_t {
    INITIAL,
    CREATE_SOCKET,
    SEND_PACKET,
    RECEIVE_PACKET,
    PREPARE_FIRST_FORWARD,
    FIRST_ANSWER,
    PREPARE_SECOND_FORWARD,
    A_REQUEST_SENT,
    NEXT_RESOLVER,
    FINISHED
};

/**
 * @brief The DNSSEC specific state of the current task
 *
 */
enum class DnssecState : uint8_t {
    NON_DNSSEC,
    PREPARE_DNSSEC,
    DNSKEY_REQUEST,
    PREPARE_DNSKEY,
    DNSKEY_RESPONSE,
    NS_LIST_REQUEST,
    PREPARE_NS_LIST,
    NS_LIST_RESPONSE,
    NS_AAAA_REQUEST,
    PREPARE_NS_AAAA,
    NS_AAAA_RESPONSE,
    NS_A_REQUEST,
    PREPARE_NS_A,
    NS_A_RESPONSE,
    DS_AAAA_REQUEST,
    DS_A_REQUEST,
    PREPARE_DS,
    DS_RESPONSE
};

/**
 * @brief The type of buffer
 *
 */
enum class BufferType : uint8_t {
    REQUEST_BUFFER,
    ANSWER_BUFFER,
    COPY_BUFFER,
    KEY_REQUEST_BUFFER,
    KEY_ANSWER_BUFFER,
    LIST_BUFFER,
    ADDRESS_BUFFER,
    DS_BUFFER,
    FORGED_BUFFER
};

enum class SocketType : uint8_t {
    RESOLVER_SOCKET,
    DELEGATION_SOCKET
};

enum class SocketCreationResult : uint8_t {
    SUCCESS,
    CREATION_FAILURE,
    RECEIVE_TIMEOUT_FAILURE,
    SEND_TIMEOUT_FAILURE
};

class Task {
        /**
         * @brief Convenience variable converting between seconds and milliseconds
         *
         */
        static constexpr uint16_t SEC_MSEC = 1000U;

    public:
        using timer_guard = std::shared_ptr<Task*>;

        /**
         * @brief Returns whether the first timer_guard is later than the second (a nullptr indicates an earlier value)
         *
         */
        struct greaterComparator {
            auto operator() (const timer_guard &timer1, const timer_guard &timer2) -> bool {
                const Task *first = *timer1;
                const Task *second = *timer2;

                if (nullptr == first) {
                    return false;
                }

                if (nullptr == second) {
                    return true;
                }

                return first->getStartTime() > second->getStartTime();
            }
        };

        using timer_queue = std::priority_queue<timer_guard, std::vector<timer_guard>, Task::greaterComparator>;
    private:
        /**
         * @brief Priority queue of timer guards, where the highest priority item is the earliest expiring one (or a nullptr if applicable)
         *
         */
        timer_queue *timerQueue{nullptr};

        /**
         * @brief The timer guard of the current task, indicating whether the task is active (containing the current instance), or expired (nullptr)
         *
         */
        timer_guard timerGuard{nullptr};

        /**
         * @brief The point in time from which the expiry of the task is calculated
         *
         */
        std::chrono::steady_clock::time_point start_time;

        /**
         * @brief Whether the timer is activated for the current task
         *
         */
        bool isTimerSet{false};

        /**
         * @brief The amount of timeouts left before the task expires
         *
         */
        int remainingTimeouts{0};

        /**
         * @brief The file descriptor of the central timer
         *
         */
        int central_socket_fd{-1};

        /**
         * @brief The current configuration instance
         *
         */
        const Configuration &configuration;

        /**
         * @brief The socket where the query was received from
         *
         */
        int receiver_socket{};

        /**
         * @brief The socket used for communicating with the resolver (or -1 if one is not active at the moment)
         *
         */
        int query_socket{-1};

        /**
         * @brief The socket used for performing delegation follow-up
         * 
         */
        int delegation_socket{-1};

        /**
         * @brief The buffer possibly containing the request
         *
         */
        DnsMessage request_buffer;

        /**
         * @brief The buffer possibly containing an answer
         *
         */
        DnsMessage answer_buffer;

        /**
         * @brief The buffer possibly containing a copy of the request
         *
         */
        DnsMessage copy_buffer;

        /**
         * @brief The buffer possibly containing a DNSKEY/NS_LIST request
         *
         */
        DnsMessage key_request_buffer;

        /**
         * @brief The buffer possibly containing a DNSKEY answer
         *
         */
        DnsMessage key_answer_buffer;

        /**
         * @brief The buffer possibly containing an NS_LIST answer
         *
         */
        DnsMessage list_buffer;

        /**
         * @brief The buffer possibly containing an address
         * 
         */
        DnsMessage address_buffer;

        /**
         * @brief The buffer possibly containing a DS answer
         *
         */
        DnsMessage ds_buffer;

        /**
         * @brief The buffer possibly containing a forged DNS64 message
         *
         */
        DnsMessage forged_buffer;

        /**
         * @brief The length of the sender of the original query
         *
         */
        socklen_t sender_length{};

        /**
         * @brief The sender of the original query
         *
         */
        struct sockaddr_in6 sender {};

        /**
         * @brief Storage holding the address for delegation
         * 
         */
        struct sockaddr_storage delegation_address {};

        /**
         * @brief The state the task will be in after a successful receive or send operation
         *
         */
        TaskState nextState{TaskState::FINISHED};

        /**
         * @brief The current state the task is in
         *
         */
        TaskState state{TaskState::INITIAL};

        /**
         * @brief The current DNSSEC state the task is in
         *
         */
        DnssecState dnssecState{DnssecState::NON_DNSSEC};

        /**
         * @brief The DNSSEC state the task will be in after a successful receive or send operation
         *
         */
        DnssecState nextDnssecState{DnssecState::NON_DNSSEC};

        /**
         * @brief The current QR type (request or response) used by a send operation
         *
         */
        DnsMessage::QrType currentQr{DnsMessage::QrType::REQUEST};

        /**
         * @brief The type of buffer currently used by the send and receive operations
         *
         */
        BufferType currentBuffer{BufferType::REQUEST_BUFFER};

        /**
         * @brief The type of buffer used for RRSig validation
         * 
         */
        BufferType rrsigBuffer{BufferType::REQUEST_BUFFER};

        /**
         * @brief The type of the currently used request socket
         * 
         */
        SocketType socketType{SocketType::RESOLVER_SOCKET};

        /**
         * @brief The current UDP payload size (and thus maximum buffer size) used
         *
         */
        uint16_t udpPayloadSize{0};

        /**
         * @brief The identifier of the currently used resolver
         *
         */
        uint16_t currentResolver{0};

        /**
         * @brief The current attempt that is executed
         *
         */
        uint16_t attempt{0};

        /**
         * @brief The original query type to be restored after the request is sent out with the current query type
         *
         */
        DnsMessage::RecordType originalQueryType{DnsMessage::RecordType::NO_VALUE};
    public:
        Task(const Configuration &configuration, int receiver_socket, std::unique_ptr<uint8_t[]> buffer, socklen_t sender_length, struct sockaddr_in6 sender, ssize_t receive_length) :
            configuration(configuration), receiver_socket(receiver_socket), request_buffer(std::move(buffer), configuration.getUdpPayloadSize(), receive_length),
            sender_length(sender_length), sender(sender), udpPayloadSize(configuration.getUdpPayloadSize()) {
            start_time = std::chrono::steady_clock::now();
        }
        explicit Task(const Configuration &configuration, ssize_t receive_length = DnsMessage::DNS_HEADER_LENGTH) : configuration(configuration),
            request_buffer(configuration.getUdpPayloadSize(), receive_length), udpPayloadSize(configuration.getUdpPayloadSize()) {
            start_time = std::chrono::steady_clock::now();
        }
        Task(const Task&) = delete;
        auto operator=(const Task&) -> Task& = delete;

        [[nodiscard]] auto getCurrentAttempt() const -> uint16_t {
            return attempt;
        }

        /**
         * @brief Compares the current time to the start time of the task
         *
         * @return std::chrono::milliseconds The amount of time in milliseconds elapsed between the start and the current time
         */
        [[nodiscard]] auto getElapsedTime() const -> std::chrono::milliseconds {
            auto current_time = std::chrono::steady_clock::now();
            return std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time);
        }

        [[nodiscard]] auto getStartTime() const -> std::chrono::steady_clock::time_point {
            return start_time;
        }

        [[nodiscard]] auto getTimerArmState() const -> bool {
            return isTimerSet;
        }

        [[nodiscard]] auto getRemainingTimeouts() const -> int {
            return remainingTimeouts;
        }

        void decrementRemainingTimeouts() {
            --remainingTimeouts;
        }

        void incrementRemainingTimeouts() {
            ++remainingTimeouts;
        }

        void setTimerArmState(bool isTimerSet) {
            this->isTimerSet = isTimerSet;
        }

        void setTimerQueue(timer_queue *queue) {
            timerQueue = queue;
        }

        /**
         * @brief The timer guard becomes a nullptr and the number remaining timeouts is zeroed out
         *
         */
        void invalidateTimer() {
            *timerGuard.get() = nullptr;
            remainingTimeouts = 0;
        }

        [[nodiscard]] auto getTimerGuard() const -> timer_guard {
            return timerGuard;
        }

        void setTimerGuard(timer_guard guard) {
            timerGuard = std::move(guard);
        }

        void setCentralSocket(int socket) {
            central_socket_fd = socket;
        }

        auto createSocket(const sockaddr_storage &address, int *socket_descriptor) -> SocketCreationResult;

        /**
         * @brief Resets the start time to the current time and pushes its timer guard into the queue (if the timer is not armed, it arms the timer)
         *
         * @return true There was no timer guard set, the timer could be added (with possibly arming the timer successfully)
         * @return false The timer could not be armed
         */
        [[nodiscard]] auto resetElapsedTime() -> bool {
            if (nullptr == timerQueue || nullptr == timerGuard) {
                return true;
            }

            incrementRemainingTimeouts();
            start_time = std::chrono::steady_clock::now();

            if (!timerQueue->empty()) {
                timerQueue->push(timerGuard);
                return true;
            }

            timerQueue->push(timerGuard);

            auto resultTime = start_time + std::chrono::milliseconds(configuration.getTimeout());
            auto secs = std::chrono::time_point_cast<std::chrono::seconds>(resultTime);
            auto nanosecs = std::chrono::time_point_cast<std::chrono::nanoseconds>(resultTime) - std::chrono::time_point_cast<std::chrono::nanoseconds>(secs);

            struct itimerspec new_value {};

            new_value.it_value.tv_sec = secs.time_since_epoch().count();
            new_value.it_value.tv_nsec = nanosecs.count();

            if (-1 == timerfd_settime(central_socket_fd, TFD_TIMER_ABSTIME, &new_value, nullptr)) {
                syslog(LOG_DEBUG, "Could not reset timer: %s", strerror(errno));
                return false;
            }

            return true;
        }

        auto handleNextResolverState() -> bool;

        auto handleInitialState() -> bool;

        auto handleCreateSocketState() -> bool;

        auto handleSendPacketState() -> bool;

        auto handleReceivePacketState() -> bool;

        auto handleFirstAnswerState() -> bool;

        auto handleARequestSentState() -> bool;

        auto handlePrepareDnssecState() -> bool;

        auto handleDnskeyRequestState() -> bool;

        auto handleDnskeyResponseState() -> bool;

        auto handleNsListRequestState() -> bool;

        auto handleNsListResponseState() -> bool;

        auto handleNsAaaaRequestState() -> bool;

        auto handleNsAaaaResponseState() -> bool;

        auto handleNsARequestState() -> bool;

        auto handleNsAResponseState() -> bool;

        auto handleDsRequest() -> bool;

        auto handleDsResponse() -> bool;

        /**
         * @brief Attempts to execute the current state of the task and push it to the next one
         *
         * @return true The new state is final or a time-consuming operation failed (socket create, send, receive)
         * @return false The new state is not final and it is not after an attempt at a time-consuming operation
         */
        auto handleState() -> bool;

        /**
         * @brief Executes task states until the state of the task is final, or it is after an attempt at a time-consuming operation
         *
         */
        void handleStateWrapper();

        [[nodiscard]] auto getState() const -> TaskState {
            return state;
        }

        void setState(TaskState state) {
            this->state = state;
        }

        [[nodiscard]] auto getNextState() const -> TaskState {
            return nextState;
        }

        [[nodiscard]] auto getDnssecState() const -> DnssecState {
            return dnssecState;
        }

        void setDnssecState(DnssecState dnssecState) {
            this->dnssecState = dnssecState;
        }

        [[nodiscard]] auto getDnssecNextState() const -> DnssecState {
            return nextDnssecState;
        }

        [[nodiscard]] auto getCurrentBuffer() -> DnsMessage * {
            return getBufferByType(currentBuffer);
        }

        [[nodiscard]] auto getCurrentBufferType() const -> BufferType {
            return currentBuffer;
        }

        void setRrsigBuffer(BufferType type) {
            rrsigBuffer = type;
        }

        [[nodiscard]] auto getCurrentQr() const -> DnsMessage::QrType {
            return currentQr;
        }

        [[nodiscard]] auto getSocket() const -> int {
            return query_socket;
        }

        [[nodiscard]] auto getDelegationSocket() const -> int {
            return delegation_socket;
        }

        [[nodiscard]] auto getCurrentResolver() const -> int {
            return currentResolver;
        }

        void printState();

        void storeOriginalType(const DnsMessage &query) {
            if (originalQueryType != DnsMessage::RecordType::NO_VALUE) {
                return;
            }

            query.getQueryType(&originalQueryType);
        }

        /**
         * @brief Receives a message to the specified buffer
         *
         * @param type The buffer to receive the message into
         * @return true An expected packet was received
         * @return false No packet was received, the packet is too short or erroneous (in the latter case the state is set to NEXT_RESOLVER)
         */
        auto receivePacket(BufferType type) -> bool;

        auto getBufferByType(BufferType type) -> DnsMessage *;

        void setBufferByType(BufferType type, std::unique_ptr<uint8_t[]> buffer, ssize_t capacity = DnsMessage::DNS_HEADER_LENGTH);

        /**
         * @brief Sends a message using the specified buffer with the specified target
         *
         * @param type The buffer to send the message from
         * @param qrType The target of the message (request = resolver, response = client)
         * @return true The message was successfully sent
         * @return false There was an issue during the sending of the message
         */
        auto sendRequest(BufferType type, DnsMessage::QrType qrType) -> bool;

        ~Task() {
            if (query_socket > -1) {
                close(query_socket);
            }

            if (delegation_socket > -1) {
                close(delegation_socket);
            }
        }
};

#endif // DNS64SEC_TASK_H