#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "doctest/trompeloeil.hpp"

#include "DnsMessage.h"
#include "DnskeyBuilder.h"
#include "NsBuilder.h"
#include "RRSigBuilder.h"
#include "Task.h"

#include <cstdarg>
#include <sys/ioctl.h>

struct NetworkMock {
    MAKE_MOCK1(close, int(int fd));
    MAKE_MOCK3(ioctl, int(int fd, unsigned long request, void* arg));
    MAKE_MOCK4(recv, ssize_t(int, void*, size_t, int));
    MAKE_MOCK6(sendto, ssize_t(int, const void*, size_t, int, const struct sockaddr*, socklen_t));
    MAKE_MOCK5(setsockopt, int(int, int, int, const void*, socklen_t));
    MAKE_MOCK3(socket, int(int, int, int));
    MAKE_MOCK1(time, time_t(time_t *__timer));
    MAKE_MOCK4(timerfd_settime, int(int, int, const struct itimerspec*, struct itimerspec*));
};

inline thread_local NetworkMock* current_mock = nullptr;

extern "C" {
    int __real_close(int fd);
    int __real_ioctl(int fd, unsigned long op, ...);
    ssize_t __real_recv(int sockfd, void *buf, size_t len, int flags);
    ssize_t __real_sendto(int sockfd, const void *buf, size_t len, int flags,
                          const struct sockaddr *dest_addr, socklen_t addrlen);
    int __real_setsockopt(int sockfd, int level, int optname, const void *optval,
                          socklen_t optlen);
    int __real_socket(int domain, int type, int protocol);
    time_t __real_time(time_t *__timer);
    int __real_timerfd_settime(int fd, int flags, const struct itimerspec *new_value,
                               struct itimerspec *old_value);

    int __wrap_close(int fd) {
        if (current_mock) {
            return current_mock->close(fd);
        }

        return __real_close(fd);
    }

    int __wrap_ioctl(int fd, unsigned long request, ...) {
        va_list args;
        va_start(args, request);

        void* arg = va_arg(args, void*);
        va_end(args);

        if (current_mock) {
            return current_mock->ioctl(fd, request, arg);
        }

        return __real_ioctl(fd, request, arg);
    }

    ssize_t __wrap_recv(int sockfd, void *buf, size_t len, int flags) {
        if (current_mock) {
            return current_mock->recv(sockfd, buf, len, flags);
        }

        return __real_recv(sockfd, buf, len, flags);
    }

    ssize_t __wrap_sendto(int sockfd, const void *buf, size_t len, int flags,
                            const struct sockaddr *dest_addr, socklen_t addrlen) {
        if (current_mock) {
            return current_mock->sendto(sockfd, buf, len, flags, dest_addr, addrlen);
        }

        return __real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    }

    int __wrap_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
        if (current_mock) {
            return current_mock->setsockopt(sockfd, level, optname, optval, optlen);
        }

        return __real_setsockopt(sockfd, level, optname, optval, optlen); 
    }

    int __wrap_socket(int domain, int type, int protocol) {
        if (current_mock) {
            return current_mock->socket(domain, type, protocol);
        }

        return __real_socket(domain, type, protocol);
    }

    time_t __wrap_time(time_t *__timer) {
        if (current_mock) {
            return current_mock->time(__timer);
        }

        return __real_time(__timer);
    }

    int __wrap_timerfd_settime(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *old_value) {
        if (current_mock) {
            return current_mock->timerfd_settime(fd, flags, new_value, old_value);
        }

        return __real_timerfd_settime(fd, flags, new_value, old_value);
    }
}

/**
 * @brief Return FORMERR if there are no question records
 * 
 */
TEST_CASE("zero question records") {
    Configuration configuration;

    Task task(configuration);

    task.handleState();

    DnsMessage *answerMessage = task.getCurrentBuffer();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    task.getBufferByType(BufferType::REQUEST_BUFFER)->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    answerMessage->printMessage(stream, true);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::SEND_PACKET);
    CHECK(task.getCurrentBufferType() == BufferType::REQUEST_BUFFER);
    CHECK(task.getCurrentQr() == DnsMessage::QrType::RESPONSE);
    CHECK(task.getNextState() == TaskState::FINISHED);

    CHECK(answerMessage->getType() == DnsMessage::QrType::RESPONSE);
    CHECK(answerMessage->getResponseCode() == DnsMessage::ResponseCode::FORMERR);
}

/**
 * @brief Do not respond if a response is the first packet
 * 
 */
TEST_CASE("response as first packet") {
    Configuration configuration;

    Task task(configuration);

    DnsMessage *questionMessage = task.getBufferByType(BufferType::REQUEST_BUFFER);

    task.getBufferByType(BufferType::REQUEST_BUFFER)->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);

    task.handleState();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::FINISHED);
}

/**
 * @brief Return NOTIMP on non-query OPCODEs
 * 
 */
TEST_CASE("non-query opcode") {
    Configuration configuration;

    Task task(configuration);

    DnsMessage *questionMessage = task.getBufferByType(BufferType::REQUEST_BUFFER);

    DnsMessage::DnsHeader *header = reinterpret_cast<DnsMessage::DnsHeader*>(questionMessage->getBuffer());

    header->opcode = 1;

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->setQueryCount(1);

    task.handleState();

    DnsMessage *answerMessage = task.getCurrentBuffer();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    answerMessage->printMessage(stream, true);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::SEND_PACKET);
    CHECK(task.getCurrentBufferType() == BufferType::REQUEST_BUFFER);
    CHECK(task.getCurrentQr() == DnsMessage::QrType::RESPONSE);
    CHECK(task.getNextState() == TaskState::FINISHED);

    CHECK(answerMessage->getType() == DnsMessage::QrType::RESPONSE);
    CHECK(answerMessage->getResponseCode() == DnsMessage::ResponseCode::NOTIMP);
}

/**
 * @brief Continue processing requests without an OPT record
 * 
 */
TEST_CASE("request without opt record is valid") {
    Configuration configuration;

    Task task(configuration);

    DnsMessage *questionMessage = task.getBufferByType(BufferType::REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->setQueryCount(1);

    task.handleState();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::CREATE_SOCKET);
}

/**
 * @brief Return FORMERR if there are multiple OPT records
 * 
 */
TEST_CASE("request with two opt records is invalid") {
    Configuration configuration;

    Task task(configuration);

    DnsMessage *questionMessage = task.getBufferByType(BufferType::REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("");
    questionMessage->addOPT();
    questionMessage->addOPT();

    task.handleState();

    DnsMessage *answerMessage = task.getCurrentBuffer();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    answerMessage->printMessage(stream, true);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::SEND_PACKET);
    CHECK(task.getCurrentBufferType() == BufferType::REQUEST_BUFFER);
    CHECK(task.getCurrentQr() == DnsMessage::QrType::RESPONSE);
    CHECK(task.getNextState() == TaskState::FINISHED);

    CHECK(answerMessage->getType() == DnsMessage::QrType::RESPONSE);
    CHECK(answerMessage->getResponseCode() == DnsMessage::ResponseCode::FORMERR);
}

/**
 * @brief Return BADVERS if the EDNS version is unsupported
 * 
 */
TEST_CASE("request with unsupported EDNS version") {
    Configuration configuration;

    Task task(configuration);

    DnsMessage *questionMessage = task.getBufferByType(BufferType::REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("");
    questionMessage->addOPT(configuration.getUdpPayloadSize(), DnsMessage::ResponseCode::NOERROR, 1);

    task.handleState();

    DnsMessage *answerMessage = task.getCurrentBuffer();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    answerMessage->printMessage(stream, true);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::SEND_PACKET);
    CHECK(task.getCurrentBufferType() == BufferType::REQUEST_BUFFER);
    CHECK(task.getCurrentQr() == DnsMessage::QrType::RESPONSE);
    CHECK(task.getNextState() == TaskState::FINISHED);

    CHECK(answerMessage->getType() == DnsMessage::QrType::RESPONSE);
    CHECK(answerMessage->getResponseCode() == DnsMessage::ResponseCode::BADVERS);
}

/**
 * @brief Continue processing with one OPT record
 * 
 */
TEST_CASE("request with one opt record is valid") {
    Configuration configuration;

    Task task(configuration);

    DnsMessage *questionMessage = task.getBufferByType(BufferType::REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("");
    questionMessage->addOPT(1024);

    task.handleState();

    DnsMessage *answerMessage = task.getCurrentBuffer();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    answerMessage->printMessage(stream, true);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::CREATE_SOCKET);
}

/**
 * @brief Skip processing if receiving a request as a response
 * 
 */
TEST_CASE("request as first response") {
    Configuration configuration;

    auto answerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    Task task(configuration);

    task.setState(TaskState::FIRST_ANSWER);
    task.setBufferByType(BufferType::ANSWER_BUFFER, std::move(answerBuffer));

    task.handleState();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    task.getBufferByType(BufferType::REQUEST_BUFFER)->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    task.getBufferByType(BufferType::ANSWER_BUFFER)->printMessage(stream, true);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::RECEIVE_PACKET);
    CHECK(task.getCurrentBufferType() == BufferType::ANSWER_BUFFER);
    CHECK(task.getNextState() == TaskState::FIRST_ANSWER);
}

/**
 * @brief Skip processing if receiving a response that is not to the question
 * 
 */
TEST_CASE("first response is not to question") {
    Configuration configuration;

    auto answerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    Task task(configuration);

    DnsMessage *questionMessage = task.getBufferByType(BufferType::REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("example", DnsMessage::RecordType::A);

    task.setState(TaskState::FIRST_ANSWER);
    task.setBufferByType(BufferType::ANSWER_BUFFER, std::move(answerBuffer));

    DnsMessage *answerMessage = task.getBufferByType(BufferType::ANSWER_BUFFER);

    answerMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    answerMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    answerMessage->addQuestion("not-example", DnsMessage::RecordType::A);

    task.handleState();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    answerMessage->printMessage(stream, true);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::RECEIVE_PACKET);
    CHECK(task.getCurrentBufferType() == BufferType::ANSWER_BUFFER);
    CHECK(task.getNextState() == TaskState::FIRST_ANSWER);
}

/**
 * @brief Respond with an A response on an A request
 * 
 */
TEST_CASE("A response on A request") {
    Configuration configuration;

    auto answerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    Task task(configuration);

    DnsMessage *questionMessage = task.getBufferByType(BufferType::REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("example", DnsMessage::RecordType::A);

    task.setState(TaskState::FIRST_ANSWER);
    task.setBufferByType(BufferType::ANSWER_BUFFER, std::move(answerBuffer));

    DnsMessage *answerMessage = task.getBufferByType(BufferType::ANSWER_BUFFER);

    answerMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    answerMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    answerMessage->addQuestion("example", DnsMessage::RecordType::A);
    answerMessage->addA("192.168.0.1");

    task.handleState();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    answerMessage->printMessage(stream, true);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::SEND_PACKET);
    CHECK(task.getCurrentBufferType() == BufferType::ANSWER_BUFFER);
    CHECK(task.getCurrentQr() == DnsMessage::QrType::RESPONSE);
    CHECK(task.getNextState() == TaskState::FINISHED);
}

/**
 * @brief Respond with an AAAA response on an AAAA request
 * 
 */
TEST_CASE("AAAA response on AAAA request") {
    Configuration configuration;

    auto answerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    Task task(configuration);

    DnsMessage *questionMessage = task.getBufferByType(BufferType::REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("example", DnsMessage::RecordType::AAAA);

    task.setState(TaskState::FIRST_ANSWER);
    task.setBufferByType(BufferType::ANSWER_BUFFER, std::move(answerBuffer));

    DnsMessage *answerMessage = task.getBufferByType(BufferType::ANSWER_BUFFER);

    answerMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    answerMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    answerMessage->addQuestion("example", DnsMessage::RecordType::AAAA);
    answerMessage->addAAAA("::1");

    task.handleState();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    answerMessage->printMessage(stream, true);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::SEND_PACKET);
    CHECK(task.getCurrentBufferType() == BufferType::ANSWER_BUFFER);
    CHECK(task.getCurrentQr() == DnsMessage::QrType::RESPONSE);
    CHECK(task.getNextState() == TaskState::FINISHED);
}

/**
 * @brief Start processing empty AAAA response on an AAAA request
 * 
 */
TEST_CASE("empty AAAA response on an AAAA request") {
    Configuration configuration;

    auto answerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    Task task(configuration);

    DnsMessage *questionMessage = task.getBufferByType(BufferType::REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("example", DnsMessage::RecordType::AAAA);

    task.setState(TaskState::FIRST_ANSWER);
    task.setBufferByType(BufferType::ANSWER_BUFFER, std::move(answerBuffer));

    DnsMessage *answerMessage = task.getBufferByType(BufferType::ANSWER_BUFFER);

    answerMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    answerMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    answerMessage->addQuestion("example", DnsMessage::RecordType::AAAA);

    task.handleState();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    answerMessage->printMessage(stream, true);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::SEND_PACKET);
    CHECK(task.getCurrentBufferType() == BufferType::REQUEST_BUFFER);
    CHECK(task.getCurrentQr() == DnsMessage::QrType::REQUEST);
    CHECK(task.getNextState() == TaskState::PREPARE_SECOND_FORWARD);
}

/**
 * @brief Skip processing if receiving a request as a response
 * 
 */
TEST_CASE("request as second response") {
    Configuration configuration;

    auto answerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    Task task(configuration);

    DnsMessage *questionMessage = task.getBufferByType(BufferType::REQUEST_BUFFER);

    task.setState(TaskState::A_REQUEST_SENT);
    task.setBufferByType(BufferType::ANSWER_BUFFER, std::move(answerBuffer));

    DnsMessage *answerMessage = task.getBufferByType(BufferType::ANSWER_BUFFER);

    task.handleState();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    answerMessage->printMessage(stream, true);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::RECEIVE_PACKET);
    CHECK(task.getCurrentBufferType() == BufferType::ANSWER_BUFFER);
    CHECK(task.getNextState() == TaskState::A_REQUEST_SENT);
}

/**
 * @brief Skip processing if receiving a response that is not to the question
 * 
 */
TEST_CASE("second response is not to question") {
    Configuration configuration;

    auto answerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    Task task(configuration);

    DnsMessage *questionMessage = task.getBufferByType(BufferType::REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("example", DnsMessage::RecordType::A);

    task.setState(TaskState::A_REQUEST_SENT);
    task.setBufferByType(BufferType::ANSWER_BUFFER, std::move(answerBuffer));

    DnsMessage *answerMessage = task.getBufferByType(BufferType::ANSWER_BUFFER);

    answerMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    answerMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    answerMessage->addQuestion("not-example", DnsMessage::RecordType::A);

    task.handleState();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    answerMessage->printMessage(stream, true);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::RECEIVE_PACKET);
    CHECK(task.getCurrentBufferType() == BufferType::ANSWER_BUFFER);
    CHECK(task.getNextState() == TaskState::A_REQUEST_SENT);
}

/**
 * @brief Return SERVFAIL if synthesis is not possible
 * 
 */
TEST_CASE("Perform no synthesis on non-global addresses") {
    Configuration configuration;

    configuration.loadConfiguration();

    auto answerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    Task task(configuration);

    DnsMessage *questionMessage = task.getBufferByType(BufferType::REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("example", DnsMessage::RecordType::A);

    task.setState(TaskState::A_REQUEST_SENT);
    task.setBufferByType(BufferType::ANSWER_BUFFER, std::move(answerBuffer));

    DnsMessage *answerMessage = task.getBufferByType(BufferType::ANSWER_BUFFER);

    answerMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    answerMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    answerMessage->addQuestion("example", DnsMessage::RecordType::A);
    answerMessage->addA("192.168.0.1");

    task.handleState();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    answerMessage->printMessage(stream, true);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::SEND_PACKET);
    CHECK(task.getCurrentBufferType() == BufferType::REQUEST_BUFFER);
    CHECK(task.getCurrentQr() == DnsMessage::QrType::RESPONSE);
    CHECK(task.getNextState() == TaskState::FINISHED);

    CHECK(questionMessage->getType() == DnsMessage::QrType::RESPONSE);
    CHECK(questionMessage->getResponseCode() == DnsMessage::ResponseCode::SERVFAIL);
}

/**
 * @brief Respond with synthesized record
 * 
 */
TEST_CASE("Perform synthesis on A answer") {
    Configuration configuration;

    configuration.loadConfiguration();

    auto answerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    Task task(configuration);

    DnsMessage *questionMessage = task.getBufferByType(BufferType::REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("example", DnsMessage::RecordType::A);

    task.setState(TaskState::A_REQUEST_SENT);
    task.setBufferByType(BufferType::ANSWER_BUFFER, std::move(answerBuffer));

    DnsMessage *answerMessage = task.getBufferByType(BufferType::ANSWER_BUFFER);

    answerMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    answerMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    answerMessage->addQuestion("example", DnsMessage::RecordType::A);
    answerMessage->addA("1.2.3.4");

    task.handleState();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    answerMessage->printMessage(stream, true);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::SEND_PACKET);
    CHECK(task.getCurrentBufferType() == BufferType::FORGED_BUFFER);
    CHECK(task.getCurrentQr() == DnsMessage::QrType::RESPONSE);
    CHECK(task.getNextState() == TaskState::FINISHED);
}

/**
 * @brief Respond with an empty response if the A record also doesn't exist
 * 
 */
TEST_CASE("Not found when nothing to synthetize") {
    Configuration configuration;

    configuration.loadConfiguration();

    auto answerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    Task task(configuration);

    DnsMessage *questionMessage = task.getBufferByType(BufferType::REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("example", DnsMessage::RecordType::A);

    task.setState(TaskState::A_REQUEST_SENT);
    task.setBufferByType(BufferType::ANSWER_BUFFER, std::move(answerBuffer));

    DnsMessage *answerMessage = task.getBufferByType(BufferType::ANSWER_BUFFER);

    answerMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    answerMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    answerMessage->addQuestion("example", DnsMessage::RecordType::A);

    task.handleState();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    answerMessage->printMessage(stream, true);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::SEND_PACKET);
    CHECK(task.getCurrentBufferType() == BufferType::ANSWER_BUFFER);
    CHECK(task.getCurrentQr() == DnsMessage::QrType::RESPONSE);
    CHECK(task.getNextState() == TaskState::FINISHED);
}

/**
 * @brief Drop messages shorter than DNS header size
 * 
 */
TEST_CASE("drop short messages") {
    Configuration configuration;

    configuration.loadConfiguration();

    auto remote_buffer = std::make_unique<uint8_t[]>(3);

    NetworkMock mock;
    current_mock = &mock;

    trompeloeil::sequence seq;

    REQUIRE_CALL(mock, ioctl(-1, static_cast<unsigned long>(FIONREAD), trompeloeil::_))
        .IN_SEQUENCE(seq)
        .LR_SIDE_EFFECT({
            int* bytes_out = static_cast<int*>(_3);
            *bytes_out = static_cast<int>(3);
        })
        .RETURN(0);

    REQUIRE_CALL(mock, recv(-1, trompeloeil::_, trompeloeil::_, 0))
        .IN_SEQUENCE(seq)
        .LR_SIDE_EFFECT({
            char* dest_buf = static_cast<char*>(_2);
            size_t dest_capacity = _3;
            size_t bytes_to_copy = std::min((size_t)3, dest_capacity);
            
            std::memcpy(dest_buf, remote_buffer.get(), bytes_to_copy);
        })
        .RETURN(static_cast<ssize_t>(3));
    
    Task task(configuration);
    
    task.setState(TaskState::PREPARE_FIRST_FORWARD);
    task.handleStateWrapper();

    CHECK(task.getState() == TaskState::RECEIVE_PACKET);
    CHECK(task.getNextState() == TaskState::FIRST_ANSWER);

    current_mock = nullptr;
}

/**
 * @brief Skip to next resolver if the socket is closed by the peer
 * 
 */
TEST_CASE("skip to next resolver if socket closed by peer") {
    Configuration configuration;

    configuration.loadConfiguration();

    auto remote_buffer = std::make_unique<uint8_t[]>(3);

    NetworkMock mock;
    current_mock = &mock;

    trompeloeil::sequence seq;

    REQUIRE_CALL(mock, ioctl(-1, static_cast<unsigned long>(FIONREAD), trompeloeil::_))
        .IN_SEQUENCE(seq)
        .LR_SIDE_EFFECT({
            int* bytes_out = static_cast<int*>(_3);
            *bytes_out = static_cast<int>(3);
        })
        .RETURN(0);

    REQUIRE_CALL(mock, recv(-1, trompeloeil::_, trompeloeil::_, 0))
        .IN_SEQUENCE(seq)
        .LR_SIDE_EFFECT({
            char* dest_buf = static_cast<char*>(_2);
            size_t dest_capacity = _3;
            size_t bytes_to_copy = std::min((size_t)3, dest_capacity);
            
            std::memcpy(dest_buf, remote_buffer.get(), bytes_to_copy);
        })
        .RETURN(static_cast<ssize_t>(0));
    
    Task task(configuration);
    
    task.setState(TaskState::PREPARE_FIRST_FORWARD);
    task.handleStateWrapper();

    CHECK(task.getState() == TaskState::NEXT_RESOLVER);
}

TEST_CASE("receive packet without dnssec validation") {
    Configuration configuration;

    configuration.loadConfiguration();

    auto remote_buffer = std::make_unique<uint8_t[]>(12);

    NetworkMock mock;
    current_mock = &mock;

    trompeloeil::sequence seq;

    REQUIRE_CALL(mock, ioctl(-1, static_cast<unsigned long>(FIONREAD), trompeloeil::_))
        .IN_SEQUENCE(seq)
        .LR_SIDE_EFFECT({
            int* bytes_out = static_cast<int*>(_3);
            *bytes_out = static_cast<int>(12);
        })
        .RETURN(0);

    REQUIRE_CALL(mock, recv(-1, trompeloeil::_, trompeloeil::_, 0))
        .IN_SEQUENCE(seq)
        .LR_SIDE_EFFECT({
            char* dest_buf = static_cast<char*>(_2);
            size_t dest_capacity = _3;
            size_t bytes_to_copy = std::min((size_t)12, dest_capacity);
            
            std::memcpy(dest_buf, remote_buffer.get(), bytes_to_copy);
        })
        .RETURN(static_cast<ssize_t>(12));
    
    Task task(configuration);
    
    task.setState(TaskState::PREPARE_FIRST_FORWARD);
    task.handleState();
    task.handleState();

    CHECK(task.getState() == TaskState::FIRST_ANSWER);
    CHECK(task.getDnssecState() == DnssecState::NON_DNSSEC);

    current_mock = nullptr;
}

TEST_CASE("fail to create a socket") {
    Configuration configuration;

    configuration.loadConfiguration();

    NetworkMock mock;
    current_mock = &mock;

    REQUIRE_CALL(mock, socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP))
        .RETURN(-1);

    Task task(configuration);

    task.setState(TaskState::CREATE_SOCKET);
    task.handleState();

    CHECK(task.getSocket() == -1);

    current_mock = nullptr;
}

TEST_CASE("fail to set receive timeout") {
    Configuration configuration;

    configuration.loadConfiguration();

    NetworkMock mock;
    current_mock = &mock;

    REQUIRE_CALL(mock, socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP))
        .RETURN(1);

    REQUIRE_CALL(mock, setsockopt(1, SOL_SOCKET, SO_RCVTIMEO, trompeloeil::_, sizeof(struct timeval)))
        .RETURN(-1);
    
    REQUIRE_CALL(mock, close(1)).RETURN(0);

    Task task(configuration);

    task.setState(TaskState::CREATE_SOCKET);
    task.handleState();

    CHECK(task.getSocket() == -1);

    current_mock = nullptr;
}

TEST_CASE("fail to set send timeout") {
    Configuration configuration;

    configuration.loadConfiguration();

    NetworkMock mock;
    current_mock = &mock;

    REQUIRE_CALL(mock, socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP))
        .RETURN(1);

    REQUIRE_CALL(mock, setsockopt(1, SOL_SOCKET, SO_RCVTIMEO, trompeloeil::_, sizeof(struct timeval)))
        .RETURN(1);

    REQUIRE_CALL(mock, setsockopt(1, SOL_SOCKET, SO_SNDTIMEO, trompeloeil::_, sizeof(struct timeval)))
        .RETURN(-1);

    REQUIRE_CALL(mock, close(1)).RETURN(0);

    Task task(configuration);

    task.setState(TaskState::CREATE_SOCKET);
    task.handleState();

    CHECK(task.getSocket() == -1);

    current_mock = nullptr;
}

TEST_CASE("create a socket successfully") {
    Configuration configuration;

    configuration.loadConfiguration();

    NetworkMock mock;
    current_mock = &mock;

    REQUIRE_CALL(mock, socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP))
        .RETURN(1);

    REQUIRE_CALL(mock, setsockopt(1, SOL_SOCKET, SO_RCVTIMEO, trompeloeil::_, sizeof(struct timeval)))
        .RETURN(1);

    REQUIRE_CALL(mock, setsockopt(1, SOL_SOCKET, SO_SNDTIMEO, trompeloeil::_, sizeof(struct timeval)))
        .RETURN(1);

    /** This is running after the destructor */
    REQUIRE_CALL(mock, close(1)).RETURN(0);

    {
        Task task(configuration);

        task.setState(TaskState::CREATE_SOCKET);
        task.handleState();

        CHECK(task.getSocket() == 1);
    }

    current_mock = nullptr;
}

TEST_CASE("retry happens before next resolver") {
    Configuration configuration;

    configuration.loadConfiguration();

    Task task(configuration);

    task.setState(TaskState::NEXT_RESOLVER);
    task.handleState();

    CHECK(task.getState() == TaskState::INITIAL);
    CHECK(task.getNextState() == TaskState::INITIAL);
    CHECK(task.getCurrentAttempt() == 1);
}

TEST_CASE("task is finished if resolvers are exhausted") {
    Configuration configuration;

    configuration.loadConfiguration();
    configuration.setAttempts(1);
    configuration.clearResolvers();
    configuration.addResolver("10.0.0.1");

    Task task(configuration);

    task.setState(TaskState::NEXT_RESOLVER);
    task.handleState();

    CHECK(task.getState() == TaskState::FINISHED);
    CHECK(task.getCurrentAttempt() == 0);
}

TEST_CASE("next resolver is selected after retries") {
    Configuration configuration;

    configuration.loadConfiguration();
    configuration.setAttempts(1);
    configuration.clearResolvers();
    configuration.addResolver("10.0.0.1");
    configuration.addResolver("10.0.0.2");

    Task task(configuration);

    task.setState(TaskState::NEXT_RESOLVER);
    task.handleState();

    CHECK(task.getState() == TaskState::INITIAL);
    CHECK(task.getNextState() == TaskState::INITIAL);
    CHECK(task.getCurrentAttempt() == 0);
}

TEST_CASE("send packet failure for zero question records") {
    Configuration configuration;

    NetworkMock mock;
    current_mock = &mock;

    REQUIRE_CALL(mock, sendto(0, trompeloeil::_, trompeloeil::_, 0, trompeloeil::_, trompeloeil::_))
        .RETURN(-1);

    Task task(configuration);

    task.handleState();

    CHECK(task.getState() == TaskState::SEND_PACKET);

    task.handleState();

    CHECK(task.getState() == TaskState::SEND_PACKET);

    current_mock = nullptr;
}

TEST_CASE("send packet successful for zero question records") {
    Configuration configuration;

    NetworkMock mock;
    current_mock = &mock;

    REQUIRE_CALL(mock, sendto(0, trompeloeil::_, trompeloeil::_, 0, trompeloeil::_, trompeloeil::_))
        .RETURN(12);

    Task task(configuration);

    task.handleState();

    CHECK(task.getState() == TaskState::SEND_PACKET);

    task.handleState();

    CHECK(task.getState() == TaskState::FINISHED);

    current_mock = nullptr;
}

TEST_CASE("dnskey request receives query instead of response") {
    Configuration configuration;

    configuration.loadConfiguration();
    configuration.setDnssecValidation(true);

    auto remote_buffer = std::make_unique<uint8_t[]>(12);

    NetworkMock mock;
    current_mock = &mock;

    trompeloeil::sequence seq;

    REQUIRE_CALL(mock, ioctl(-1, static_cast<unsigned long>(FIONREAD), trompeloeil::_))
        .IN_SEQUENCE(seq)
        .LR_SIDE_EFFECT({
            int* bytes_out = static_cast<int*>(_3);
            *bytes_out = static_cast<int>(12);
        })
        .RETURN(0);

    REQUIRE_CALL(mock, recv(-1, trompeloeil::_, trompeloeil::_, 0))
        .IN_SEQUENCE(seq)
        .LR_SIDE_EFFECT({
            char* dest_buf = static_cast<char*>(_2);
            size_t dest_capacity = _3;
            size_t bytes_to_copy = std::min((size_t)12, dest_capacity);
            
            std::memcpy(dest_buf, remote_buffer.get(), bytes_to_copy);
        })
        .RETURN(static_cast<ssize_t>(12));
    
    Task task(configuration);
    
    task.setState(TaskState::PREPARE_FIRST_FORWARD);
    task.handleState();
    task.handleState();
    task.handleState();

    CHECK(task.getState() == TaskState::FIRST_ANSWER);
    CHECK(task.getDnssecState() == DnssecState::DNSKEY_REQUEST);

    task.handleState();

    CHECK(task.getState() == TaskState::RECEIVE_PACKET);
    CHECK(task.getNextState() == TaskState::FIRST_ANSWER);
    CHECK(task.getDnssecState() == DnssecState::NON_DNSSEC);

    current_mock = nullptr;
}

TEST_CASE("dnskey request non-matching question") {
    Configuration configuration;

    configuration.loadConfiguration();
    configuration.setDnssecValidation(true);

    DnsMessage answerMessage(configuration.getUdpPayloadSize());

    answerMessage.setSize(DnsMessage::DNS_HEADER_LENGTH);
    answerMessage.modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    answerMessage.addQuestion("not-example", DnsMessage::RecordType::A);

    auto answerSize = answerMessage.getSize();

    NetworkMock mock;
    current_mock = &mock;

    trompeloeil::sequence seq;

    REQUIRE_CALL(mock, ioctl(-1, static_cast<unsigned long>(FIONREAD), trompeloeil::_))
        .IN_SEQUENCE(seq)
        .LR_SIDE_EFFECT({
            int* bytes_out = static_cast<int*>(_3);
            *bytes_out = static_cast<int>(answerMessage.getSize());
        })
        .RETURN(0);

    REQUIRE_CALL(mock, recv(-1, trompeloeil::_, trompeloeil::_, 0))
        .IN_SEQUENCE(seq)
        .LR_SIDE_EFFECT({
            char* dest_buf = static_cast<char*>(_2);
            size_t dest_capacity = _3;
            size_t bytes_to_copy = std::min((size_t)answerMessage.getSize(), dest_capacity);
            
            std::memcpy(dest_buf, answerMessage.getBuffer(), bytes_to_copy);
        })
        .RETURN(answerSize);
    
    Task task(configuration);

    DnsMessage *questionMessage = task.getBufferByType(BufferType::REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("example", DnsMessage::RecordType::A);
    
    task.setState(TaskState::PREPARE_FIRST_FORWARD);
    task.handleState();
    task.handleState();
    task.handleState();

    CHECK(task.getState() == TaskState::FIRST_ANSWER);
    CHECK(task.getDnssecState() == DnssecState::DNSKEY_REQUEST);

    task.handleState();

    CHECK(task.getState() == TaskState::RECEIVE_PACKET);
    CHECK(task.getNextState() == TaskState::FIRST_ANSWER);
    CHECK(task.getDnssecState() == DnssecState::NON_DNSSEC);

    current_mock = nullptr;
}

TEST_CASE("dnskey request missing rrsig in the response") {
    Configuration configuration;

    configuration.loadConfiguration();
    configuration.setDnssecValidation(true);

    DnsMessage answerMessage(configuration.getUdpPayloadSize());

    answerMessage.setSize(DnsMessage::DNS_HEADER_LENGTH);
    answerMessage.modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    answerMessage.addQuestion("example", DnsMessage::RecordType::A);

    NetworkMock mock;
    current_mock = &mock;

    trompeloeil::sequence seq;

    auto answerSize = answerMessage.getSize();

    REQUIRE_CALL(mock, ioctl(-1, static_cast<unsigned long>(FIONREAD), trompeloeil::_))
        .IN_SEQUENCE(seq)
        .LR_SIDE_EFFECT({
            int* bytes_out = static_cast<int*>(_3);
            *bytes_out = static_cast<int>(answerMessage.getSize());
        })
        .RETURN(0);

    REQUIRE_CALL(mock, recv(-1, trompeloeil::_, trompeloeil::_, 0))
        .IN_SEQUENCE(seq)
        .LR_SIDE_EFFECT({
            char* dest_buf = static_cast<char*>(_2);
            size_t dest_capacity = _3;
            size_t bytes_to_copy = std::min((size_t)answerMessage.getSize(), dest_capacity);
            
            std::memcpy(dest_buf, answerMessage.getBuffer(), bytes_to_copy);
        })
        .RETURN(answerSize);
    
    Task task(configuration);

    DnsMessage *questionMessage = task.getBufferByType(BufferType::REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("example", DnsMessage::RecordType::A);
    
    task.setState(TaskState::PREPARE_FIRST_FORWARD);
    task.handleState();
    task.handleState();
    task.handleState();

    CHECK(task.getState() == TaskState::FIRST_ANSWER);
    CHECK(task.getDnssecState() == DnssecState::DNSKEY_REQUEST);

    task.handleState();

    CHECK(task.getState() == TaskState::RECEIVE_PACKET);
    CHECK(task.getNextState() == TaskState::FIRST_ANSWER);
    CHECK(task.getDnssecState() == DnssecState::NON_DNSSEC);

    current_mock = nullptr;
}

TEST_CASE("dnskey request invalid rrsig timestamp") {
    Configuration configuration;

    configuration.loadConfiguration();
    configuration.setDnssecValidation(true);

    DnsMessage answerMessage(configuration.getUdpPayloadSize());

    answerMessage.setSize(DnsMessage::DNS_HEADER_LENGTH);
    answerMessage.modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    answerMessage.addQuestion("example", DnsMessage::RecordType::A);
    
    RRSigBuilder builder("example");

    builder.build(answerMessage);

    NetworkMock mock;
    current_mock = &mock;

    trompeloeil::sequence seq;

    auto answerSize = answerMessage.getSize();

    REQUIRE_CALL(mock, ioctl(-1, static_cast<unsigned long>(FIONREAD), trompeloeil::_))
        .IN_SEQUENCE(seq)
        .LR_SIDE_EFFECT({
            int* bytes_out = static_cast<int*>(_3);
            *bytes_out = static_cast<int>(answerMessage.getSize());
        })
        .RETURN(0);

    REQUIRE_CALL(mock, recv(-1, trompeloeil::_, trompeloeil::_, 0))
        .IN_SEQUENCE(seq)
        .LR_SIDE_EFFECT({
            char* dest_buf = static_cast<char*>(_2);
            size_t dest_capacity = _3;
            size_t bytes_to_copy = std::min((size_t)answerMessage.getSize(), dest_capacity);
            
            std::memcpy(dest_buf, answerMessage.getBuffer(), bytes_to_copy);
        })
        .RETURN(answerSize);
    
    REQUIRE_CALL(mock, time(nullptr))
        .IN_SEQUENCE(seq)
        .RETURN(5);
    
    Task task(configuration);

    DnsMessage *questionMessage = task.getBufferByType(BufferType::REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("example", DnsMessage::RecordType::A);
    
    task.setState(TaskState::PREPARE_FIRST_FORWARD);
    task.handleState();
    task.handleState();
    task.handleState();

    CHECK(task.getState() == TaskState::FIRST_ANSWER);
    CHECK(task.getDnssecState() == DnssecState::DNSKEY_REQUEST);

    task.handleState();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    answerMessage.printMessage(stream, true);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::RECEIVE_PACKET);
    CHECK(task.getNextState() == TaskState::FIRST_ANSWER);
    CHECK(task.getDnssecState() == DnssecState::NON_DNSSEC);

    current_mock = nullptr;
}

TEST_CASE("dnskey request type not covered by rrsig") {
    Configuration configuration;

    configuration.loadConfiguration();
    configuration.setDnssecValidation(true);

    auto answerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    DnsMessage answerMessage(configuration.getUdpPayloadSize());

    answerMessage.setSize(DnsMessage::DNS_HEADER_LENGTH);
    answerMessage.modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    answerMessage.addQuestion("example", DnsMessage::RecordType::A);
    
    RRSigBuilder builder("example");

    builder.setSignatureInception(1).setSignatureExpiration(10).build(answerMessage);

    NetworkMock mock;
    current_mock = &mock;

    trompeloeil::sequence seq;

    auto answerSize = answerMessage.getSize();

    REQUIRE_CALL(mock, ioctl(-1, static_cast<unsigned long>(FIONREAD), trompeloeil::_))
        .IN_SEQUENCE(seq)
        .LR_SIDE_EFFECT({
            int* bytes_out = static_cast<int*>(_3);
            *bytes_out = static_cast<int>(answerMessage.getSize());
        })
        .RETURN(5);

    REQUIRE_CALL(mock, recv(-1, trompeloeil::_, trompeloeil::_, 0))
        .IN_SEQUENCE(seq)
        .LR_SIDE_EFFECT({
            char* dest_buf = static_cast<char*>(_2);
            size_t dest_capacity = _3;
            size_t bytes_to_copy = std::min((size_t)answerMessage.getSize(), dest_capacity);
            
            std::memcpy(dest_buf, answerMessage.getBuffer(), bytes_to_copy);
        })
        .RETURN(answerSize);
    
    REQUIRE_CALL(mock, time(nullptr))
        .IN_SEQUENCE(seq)
        .RETURN(5);
    
    Task task(configuration);

    DnsMessage *questionMessage = task.getBufferByType(BufferType::REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("example", DnsMessage::RecordType::A);
    
    task.setState(TaskState::PREPARE_FIRST_FORWARD);
    task.handleState();
    task.handleState();
    task.handleState();

    CHECK(task.getState() == TaskState::FIRST_ANSWER);
    CHECK(task.getDnssecState() == DnssecState::DNSKEY_REQUEST);

    task.handleState();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    answerMessage.printMessage(stream, true);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::RECEIVE_PACKET);
    CHECK(task.getNextState() == TaskState::FIRST_ANSWER);
    CHECK(task.getDnssecState() == DnssecState::NON_DNSSEC);

    current_mock = nullptr;
}

TEST_CASE("dnskey request valid") {
    Configuration configuration;

    configuration.loadConfiguration();
    configuration.setDnssecValidation(true);

    DnsMessage answerMessage(configuration.getUdpPayloadSize());

    answerMessage.setSize(DnsMessage::DNS_HEADER_LENGTH);
    answerMessage.modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    answerMessage.addQuestion("example", DnsMessage::RecordType::A);
    
    RRSigBuilder builder("example");

    builder.setTypeCovered(DnsMessage::RecordType::A).setSignatureInception(1).setSignatureExpiration(10).setSignersName("example").build(answerMessage);

    NetworkMock mock;
    current_mock = &mock;

    trompeloeil::sequence seq;

    auto answerSize = answerMessage.getSize();

    REQUIRE_CALL(mock, ioctl(-1, static_cast<unsigned long>(FIONREAD), trompeloeil::_))
        .IN_SEQUENCE(seq)
        .LR_SIDE_EFFECT({
            int* bytes_out = static_cast<int*>(_3);
            *bytes_out = static_cast<int>(answerMessage.getSize());
        })
        .RETURN(answerSize);

    REQUIRE_CALL(mock, recv(-1, trompeloeil::_, trompeloeil::_, 0))
        .IN_SEQUENCE(seq)
        .LR_SIDE_EFFECT({
            char* dest_buf = static_cast<char*>(_2);
            size_t dest_capacity = _3;
            size_t bytes_to_copy = std::min((size_t)answerMessage.getSize(), dest_capacity);
            
            std::memcpy(dest_buf, answerMessage.getBuffer(), bytes_to_copy);
        })
        .RETURN(answerSize);
    
    REQUIRE_CALL(mock, time(nullptr))
        .IN_SEQUENCE(seq)
        .RETURN(5);
    
    Task task(configuration);

    DnsMessage *questionMessage = task.getBufferByType(BufferType::REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("example", DnsMessage::RecordType::A);
    
    task.setState(TaskState::PREPARE_FIRST_FORWARD);
    task.handleState();
    task.handleState();
    task.handleState();

    CHECK(task.getState() == TaskState::FIRST_ANSWER);
    CHECK(task.getDnssecState() == DnssecState::DNSKEY_REQUEST);

    task.handleState();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    answerMessage.printMessage(stream, true);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::SEND_PACKET);
    CHECK(task.getNextState() == TaskState::FIRST_ANSWER);
    CHECK(task.getDnssecState() == DnssecState::DNSKEY_REQUEST);
    CHECK(task.getDnssecNextState() == DnssecState::PREPARE_DNSKEY);

    current_mock = nullptr;
}

TEST_CASE("dnskey response receives query instead of response") {
    Configuration configuration;

    configuration.loadConfiguration();
    configuration.setDnssecValidation(true);

    auto answerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    auto dnskeyBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    Task task(configuration);

    task.setState(TaskState::FIRST_ANSWER);
    task.setDnssecState(DnssecState::DNSKEY_RESPONSE);
    task.setBufferByType(BufferType::ANSWER_BUFFER, std::move(answerBuffer));

    DnsMessage *answerMessage = task.getBufferByType(BufferType::ANSWER_BUFFER);

    answerMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    answerMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    answerMessage->addQuestion("example", DnsMessage::RecordType::A);

    RRSigBuilder builder("example");

    builder.setTypeCovered(DnsMessage::RecordType::A).setSignatureInception(1).setSignatureExpiration(10).build(*answerMessage);
    
    task.setBufferByType(BufferType::KEY_ANSWER_BUFFER, std::move(dnskeyBuffer));

    task.handleState();

    CHECK(task.getState() == TaskState::RECEIVE_PACKET);
    CHECK(task.getDnssecNextState() == DnssecState::DNSKEY_RESPONSE);
}

TEST_CASE("dnskey response non-matching question") {
    Configuration configuration;

    configuration.loadConfiguration();
    configuration.setDnssecValidation(true);

    auto answerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    auto dnskeyRequestBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    auto dnskeyResponseBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    Task task(configuration);

    task.setBufferByType(BufferType::KEY_REQUEST_BUFFER, std::move(dnskeyRequestBuffer));

    DnsMessage *questionMessage = task.getBufferByType(BufferType::KEY_REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("example", DnsMessage::RecordType::DNSKEY);

    task.setState(TaskState::FIRST_ANSWER);
    task.setDnssecState(DnssecState::DNSKEY_RESPONSE);
    task.setBufferByType(BufferType::ANSWER_BUFFER, std::move(answerBuffer));

    DnsMessage *answerMessage = task.getBufferByType(BufferType::ANSWER_BUFFER);

    answerMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    answerMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    answerMessage->addQuestion("example", DnsMessage::RecordType::A);

    RRSigBuilder builder("example");

    builder.setTypeCovered(DnsMessage::RecordType::A).setSignatureInception(1).setSignatureExpiration(10).build(*answerMessage);

    task.setBufferByType(BufferType::KEY_ANSWER_BUFFER, std::move(dnskeyResponseBuffer));

    DnsMessage *dnskeyMessage = task.getBufferByType(BufferType::KEY_ANSWER_BUFFER);

    dnskeyMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    dnskeyMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    dnskeyMessage->addQuestion("non-example", DnsMessage::RecordType::DNSKEY);

    task.handleState();

    CHECK(task.getState() == TaskState::RECEIVE_PACKET);
    CHECK(task.getDnssecNextState() == DnssecState::DNSKEY_RESPONSE);
}

TEST_CASE("dnskey response missing dnskey in the response") {
    Configuration configuration;

    configuration.loadConfiguration();
    configuration.setDnssecValidation(true);

    auto answerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    auto dnskeyRequestBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    auto dnskeyResponseBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    Task task(configuration);

    task.setBufferByType(BufferType::KEY_REQUEST_BUFFER, std::move(dnskeyRequestBuffer));

    DnsMessage *questionMessage = task.getBufferByType(BufferType::KEY_REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("example", DnsMessage::RecordType::DNSKEY);

    task.setState(TaskState::FIRST_ANSWER);
    task.setDnssecState(DnssecState::DNSKEY_RESPONSE);

    task.setBufferByType(BufferType::ANSWER_BUFFER, std::move(answerBuffer));

    DnsMessage *answerMessage = task.getBufferByType(BufferType::ANSWER_BUFFER);

    answerMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    answerMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    answerMessage->addQuestion("example", DnsMessage::RecordType::A);

    RRSigBuilder builder("example");

    builder.setTypeCovered(DnsMessage::RecordType::A).setSignatureInception(1).setSignatureExpiration(10).build(*answerMessage);

    task.setBufferByType(BufferType::KEY_ANSWER_BUFFER, std::move(dnskeyResponseBuffer));

    DnsMessage *dnskeyMessage = task.getBufferByType(BufferType::KEY_ANSWER_BUFFER);

    dnskeyMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    dnskeyMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    dnskeyMessage->addQuestion("example", DnsMessage::RecordType::DNSKEY);

    task.handleState();

    CHECK(task.getState() == TaskState::RECEIVE_PACKET);
    CHECK(task.getDnssecNextState() == DnssecState::DNSKEY_RESPONSE);
}

TEST_CASE("dnskey response missing zone key") {
    Configuration configuration;

    configuration.loadConfiguration();
    configuration.setDnssecValidation(true);

    auto answerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    auto dnskeyRequestBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    auto dnskeyAnswerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    Task task(configuration);

    task.setBufferByType(BufferType::KEY_REQUEST_BUFFER, std::move(dnskeyRequestBuffer));

    DnsMessage *questionMessage = task.getBufferByType(BufferType::KEY_REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("example", DnsMessage::RecordType::DNSKEY);

    task.setState(TaskState::FIRST_ANSWER);
    task.setDnssecState(DnssecState::DNSKEY_RESPONSE);
    task.setBufferByType(BufferType::ANSWER_BUFFER, std::move(answerBuffer));

    DnsMessage *answerMessage = task.getBufferByType(BufferType::ANSWER_BUFFER);

    answerMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    answerMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    answerMessage->addQuestion("example", DnsMessage::RecordType::A);

    RRSigBuilder builder("example");

    builder.setTypeCovered(DnsMessage::RecordType::A).setSignatureInception(1).setSignatureExpiration(10).build(*answerMessage);

    task.setBufferByType(BufferType::KEY_ANSWER_BUFFER, std::move(dnskeyAnswerBuffer));

    DnsMessage *dnskeyMessage = task.getBufferByType(BufferType::KEY_ANSWER_BUFFER);

    dnskeyMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    dnskeyMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    dnskeyMessage->addQuestion("example", DnsMessage::RecordType::DNSKEY);

    DnskeyBuilder keyBuilder("example");

    keyBuilder.build(*dnskeyMessage);

    task.handleState();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    answerMessage->printMessage(stream, true);
    stream << std::endl << "DNSKEY:" << std::endl;
    dnskeyMessage->printMessage(stream, false);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::RECEIVE_PACKET);
    CHECK(task.getDnssecNextState() == DnssecState::DNSKEY_RESPONSE);
}

TEST_CASE("dnskey response algorithm mismatch") {
    Configuration configuration;

    configuration.loadConfiguration();
    configuration.setDnssecValidation(true);

    auto dnskeyRequestBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    auto answerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    auto dnskeyAnswerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    Task task(configuration);

    task.setBufferByType(BufferType::KEY_REQUEST_BUFFER, std::move(dnskeyRequestBuffer));

    DnsMessage *questionMessage = task.getBufferByType(BufferType::KEY_REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("example", DnsMessage::RecordType::DNSKEY);

    task.setState(TaskState::FIRST_ANSWER);
    task.setDnssecState(DnssecState::DNSKEY_RESPONSE);
    task.setBufferByType(BufferType::ANSWER_BUFFER, std::move(answerBuffer));

    DnsMessage *answerMessage = task.getBufferByType(BufferType::ANSWER_BUFFER);

    answerMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    answerMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    answerMessage->addQuestion("example", DnsMessage::RecordType::A);

    RRSigBuilder builder("example");

    builder.setTypeCovered(DnsMessage::RecordType::A).setSignatureInception(1).setSignatureExpiration(10).build(*answerMessage);

    task.setBufferByType(BufferType::KEY_ANSWER_BUFFER, std::move(dnskeyAnswerBuffer));

    DnsMessage *dnskeyMessage = task.getBufferByType(BufferType::KEY_ANSWER_BUFFER);

    dnskeyMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    dnskeyMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    dnskeyMessage->addQuestion("example", DnsMessage::RecordType::DNSKEY);

    DnskeyBuilder keyBuilder("example");

    keyBuilder.setZoneKeyState().setAlgorithm(1).build(*dnskeyMessage);

    task.handleState();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    answerMessage->printMessage(stream, true);
    stream << std::endl << "DNSKEY:" << std::endl;
    dnskeyMessage->printMessage(stream, false);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::RECEIVE_PACKET);
    CHECK(task.getDnssecNextState() == DnssecState::DNSKEY_RESPONSE);
}

TEST_CASE("dnskey response key tag mismatch") {
    Configuration configuration;

    configuration.loadConfiguration();
    configuration.setDnssecValidation(true);

    auto answerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    auto dnskeyRequestBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    auto dnskeyAnswerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    NetworkMock mock;
    current_mock = &mock;

    REQUIRE_CALL(mock, time(nullptr))
        .RETURN(5);

    Task task(configuration);

    task.setBufferByType(BufferType::KEY_REQUEST_BUFFER, std::move(dnskeyRequestBuffer));

    DnsMessage *questionMessage = task.getBufferByType(BufferType::KEY_REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("example", DnsMessage::RecordType::DNSKEY);

    task.setState(TaskState::FIRST_ANSWER);
    task.setDnssecState(DnssecState::DNSKEY_RESPONSE);
    task.setBufferByType(BufferType::ANSWER_BUFFER, std::move(answerBuffer));
    task.setRrsigBuffer(BufferType::ANSWER_BUFFER);

    DnsMessage *answerMessage = task.getBufferByType(BufferType::ANSWER_BUFFER);

    answerMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    answerMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    answerMessage->addQuestion("example", DnsMessage::RecordType::A);

    RRSigBuilder builder("example");

    builder.setAlgorithm(static_cast<uint8_t>(DnsMessage::KeyType::RSA_SHA256)).setTypeCovered(DnsMessage::RecordType::DNSKEY).setSignatureInception(1).setSignatureExpiration(10).build(*answerMessage);

    task.setBufferByType(BufferType::KEY_ANSWER_BUFFER, std::move(dnskeyAnswerBuffer));

    DnsMessage *dnskeyMessage = task.getBufferByType(BufferType::KEY_ANSWER_BUFFER);

    dnskeyMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    dnskeyMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    dnskeyMessage->addQuestion("example", DnsMessage::RecordType::DNSKEY);

    DnskeyBuilder keyBuilder("example");

    keyBuilder.setZoneKeyState().setAlgorithm(static_cast<uint8_t>(DnsMessage::KeyType::RSA_SHA256)).build(*dnskeyMessage);

    task.storeOriginalType(*questionMessage);

    task.handleState();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    answerMessage->printMessage(stream, true);
    stream << std::endl << "DNSKEY:" << std::endl;
    dnskeyMessage->printMessage(stream, false);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::RECEIVE_PACKET);
    CHECK(task.getDnssecNextState() == DnssecState::DNSKEY_RESPONSE);

    current_mock = nullptr;
}

TEST_CASE("dnskey response rsa validation failure") {
    Configuration configuration;

    configuration.loadConfiguration();
    configuration.setDnssecValidation(true);

    auto dnskeyRequestBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    auto dnskeyAnswerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    auto answerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    NetworkMock mock;
    current_mock = &mock;

    REQUIRE_CALL(mock, time(nullptr))
        .RETURN(5);

    Task task(configuration);

    task.setBufferByType(BufferType::KEY_REQUEST_BUFFER, std::move(dnskeyRequestBuffer));

    DnsMessage *questionMessage = task.getBufferByType(BufferType::KEY_REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("example", DnsMessage::RecordType::DNSKEY);

    task.setState(TaskState::FIRST_ANSWER);
    task.setDnssecState(DnssecState::DNSKEY_RESPONSE);
    task.setBufferByType(BufferType::KEY_ANSWER_BUFFER, std::move(dnskeyAnswerBuffer));

    DnsMessage *dnskeyMessage = task.getBufferByType(BufferType::KEY_ANSWER_BUFFER);

    dnskeyMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    dnskeyMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    dnskeyMessage->addQuestion("example", DnsMessage::RecordType::DNSKEY);

    DnskeyBuilder keyBuilder("example");

    keyBuilder.setZoneKeyState().setAlgorithm(static_cast<uint8_t>(DnsMessage::KeyType::RSA_SHA256)).generateRsaKeyPair().build(*dnskeyMessage);

    auto [dnsKeyStart, dnsKeyAfterName] = DnsMessage::RecordParser(*dnskeyMessage).parseNext(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::DNSKEY);

    auto keyTag = dnskeyMessage->calculateKeyTag(dnsKeyAfterName);

    task.setBufferByType(BufferType::ANSWER_BUFFER, std::move(answerBuffer));
    task.setRrsigBuffer(BufferType::ANSWER_BUFFER);

    DnsMessage *answerMessage = task.getBufferByType(BufferType::ANSWER_BUFFER);

    answerMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    answerMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    answerMessage->addQuestion("example", DnsMessage::RecordType::A);

    RRSigBuilder builder("example");

    builder.setKeyTag(keyTag).setAlgorithm(static_cast<uint8_t>(DnsMessage::KeyType::RSA_SHA256)).setTypeCovered(DnsMessage::RecordType::DNSKEY).setSignatureInception(1).setSignatureExpiration(10).build(*answerMessage);

    task.storeOriginalType(*questionMessage);

    task.handleState();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    answerMessage->printMessage(stream, true);
    stream << std::endl << "DNSKEY:" << std::endl;
    dnskeyMessage->printMessage(stream, false);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::RECEIVE_PACKET);
    CHECK(task.getDnssecNextState() == DnssecState::DNSKEY_RESPONSE);

    current_mock = nullptr;
}

TEST_CASE("dnskey response rrset validation successful") {
    Configuration configuration;

    configuration.loadConfiguration();
    configuration.setDnssecValidation(true);

    auto dnskeyRequestBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    auto dnskeyAnswerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    auto answerBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    NetworkMock mock;
    current_mock = &mock;

    REQUIRE_CALL(mock, time(nullptr))
        .RETURN(5);

    Task task(configuration);

    task.setBufferByType(BufferType::KEY_REQUEST_BUFFER, std::move(dnskeyRequestBuffer));

    DnsMessage *questionMessage = task.getBufferByType(BufferType::KEY_REQUEST_BUFFER);

    questionMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    questionMessage->addQuestion("example", DnsMessage::RecordType::DNSKEY);

    task.setState(TaskState::FIRST_ANSWER);
    task.setDnssecState(DnssecState::DNSKEY_RESPONSE);
    task.setBufferByType(BufferType::KEY_ANSWER_BUFFER, std::move(dnskeyAnswerBuffer));

    DnsMessage *dnskeyMessage = task.getBufferByType(BufferType::KEY_ANSWER_BUFFER);

    dnskeyMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    dnskeyMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    dnskeyMessage->addQuestion("example", DnsMessage::RecordType::DNSKEY);

    DnskeyBuilder keyBuilder("example");

    keyBuilder.setZoneKeyState().setAlgorithm(static_cast<uint8_t>(DnsMessage::KeyType::RSA_SHA256)).generateRsaKeyPair().build(*dnskeyMessage);

    auto [dnsKeyStart, dnsKeyAfterName] = DnsMessage::RecordParser(*dnskeyMessage).parseNext(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::DNSKEY);

    auto keyTag = dnskeyMessage->calculateKeyTag(dnsKeyAfterName);

    task.setBufferByType(BufferType::ANSWER_BUFFER, std::move(answerBuffer));
    task.setRrsigBuffer(BufferType::ANSWER_BUFFER);

    DnsMessage *answerMessage = task.getBufferByType(BufferType::ANSWER_BUFFER);

    answerMessage->setSize(DnsMessage::DNS_HEADER_LENGTH);
    answerMessage->modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    answerMessage->addQuestion("example", DnsMessage::RecordType::A);
    answerMessage->addA("192.168.0.1");

    RRSigBuilder builder("example");

    builder.setPrivateKey(keyBuilder.getPrivateKey()).setKeyTag(keyTag).setAlgorithm(static_cast<uint8_t>(DnsMessage::KeyType::RSA_SHA256)).setTypeCovered(DnsMessage::RecordType::A)
        .setSignatureInception(1).setSignatureExpiration(10).build(*answerMessage);

    task.storeOriginalType(*answerMessage);

    task.handleState();

    std::stringstream stream;

    stream << "Question:" << std::endl;
    questionMessage->printMessage(stream, true);
    stream << std::endl << "Answer:" << std::endl;
    answerMessage->printMessage(stream, true);
    stream << std::endl << "DNSKEY:" << std::endl;
    dnskeyMessage->printMessage(stream, false);

    INFO(stream.str());

    CHECK(task.getState() == TaskState::RECEIVE_PACKET);
    CHECK(task.getDnssecState() == DnssecState::NON_DNSSEC);

    current_mock = nullptr;
}

TEST_CASE("ds response receives query instead of response") {
    Configuration configuration;

    configuration.loadConfiguration();
    configuration.setDnssecValidation(true);

    auto dsBuffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());

    Task task(configuration);

    task.setState(TaskState::FIRST_ANSWER);
    task.setDnssecState(DnssecState::DS_RESPONSE);
    task.setBufferByType(BufferType::DS_BUFFER, std::move(dsBuffer));

    task.handleState();

    CHECK(task.getState() == TaskState::RECEIVE_PACKET);
    CHECK(task.getDnssecNextState() == DnssecState::DS_RESPONSE);
}

TEST_CASE("order domain names in signature") {
    Configuration configuration;

    configuration.loadConfiguration();
    /** TODO: This should be dynamic instead */
    configuration.setUdpPayloadSize(1024U);

    DnsMessage dnskeyMessage(configuration.getUdpPayloadSize());

    dnskeyMessage.setSize(DnsMessage::DNS_HEADER_LENGTH);
    dnskeyMessage.modifyQueryToBeResponse(DnsMessage::ResponseCode::NOERROR);
    dnskeyMessage.addQuestion("example", DnsMessage::RecordType::DNSKEY);

    DnskeyBuilder keyBuilder("example");

    keyBuilder.setZoneKeyState().setAlgorithm(1).generateRsaKeyPair().build(dnskeyMessage);

    auto [dnsKeyStart, dnsKeyAfterName] = DnsMessage::RecordParser(dnskeyMessage).parseNext(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::DNSKEY);

    auto keyTag = dnskeyMessage.calculateKeyTag(dnsKeyAfterName);

    DnsMessage firstMessage(configuration.getUdpPayloadSize());

    firstMessage.setSize(DnsMessage::DNS_HEADER_LENGTH);

    NsBuilder nsBuilder("example");

    nsBuilder.setNameserver("y.example.com").build(firstMessage);
    nsBuilder.setNameserver("be.example.com").build(firstMessage);
    nsBuilder.setNameserver("si.example.com").build(firstMessage);
    nsBuilder.setNameserver("w.example.com").build(firstMessage);
    nsBuilder.setNameserver("x.example.com").build(firstMessage);

    RRSigBuilder sigBuilder("example");

    sigBuilder.setPrivateKey(keyBuilder.getPrivateKey()).setKeyTag(keyTag).setAlgorithm(1).setTypeCovered(DnsMessage::RecordType::NS)
        .setSignatureInception(1).setSignatureExpiration(10).build(firstMessage);

    DnsMessage secondMessage(configuration.getUdpPayloadSize());

    secondMessage.setSize(DnsMessage::DNS_HEADER_LENGTH);

    nsBuilder.setNameserver("be.example.com").build(secondMessage);
    nsBuilder.setNameserver("si.example.com").build(secondMessage);
    nsBuilder.setNameserver("w.example.com").build(secondMessage);
    nsBuilder.setNameserver("x.example.com").build(secondMessage);
    nsBuilder.setNameserver("y.example.com").build(secondMessage);

    sigBuilder.setPrivateKey(keyBuilder.getPrivateKey()).setKeyTag(keyTag).setAlgorithm(1).setTypeCovered(DnsMessage::RecordType::NS)
        .setSignatureInception(1).setSignatureExpiration(10).build(secondMessage);

    std::stringstream stream;

    stream << "DNSKEY:" << std::endl;
    dnskeyMessage.printMessage(stream, false);
    stream << "First:" << std::endl;
    firstMessage.printMessage(stream, false);
    stream << std::endl << "Second:" << std::endl;
    secondMessage.printMessage(stream, false);

    INFO(stream.str());

    CHECK(firstMessage.getAnswerCount() == 6);

    auto [firstStart, firstAfterName] = DnsMessage::RecordParser(firstMessage).parseNext(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::RRSIG);
    auto [secondStart, secondAfterName] = DnsMessage::RecordParser(secondMessage).parseNext(DnsMessage::SectionType::ANSWER, DnsMessage::RecordType::RRSIG);

    auto *firstRecordHeader = firstMessage.getRrHeader(firstAfterName);

    const int rc = std::memcmp(
        &firstMessage.getBuffer()[firstAfterName + DnsMessage::LEN_RR_FIXED],
        &secondMessage.getBuffer()[secondAfterName + DnsMessage::LEN_RR_FIXED],
        ntohs(firstRecordHeader->rdlength));

    CHECK(rc == 0);
}