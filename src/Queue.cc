/**
 * @file Queue.cc
 * @author Andras Attila Gerendas
 * @brief Queue handling class (contains receiver and worker thread functions)
 * @version 0.1
 * @date 2022-06-21
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "Queue.h"

#include "Configuration.h"
#include "DnsMessage.h"

#include <array>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <tuple>

Queue::Queue(const Configuration &configuration) : configuration(configuration) {
}

void Queue::init() {
    is_running = true;

    if (!configuration.getReceivers().empty() && !configuration.getWorkers().empty()) {
        receiver_count = configuration.getReceivers().size();
        worker_count = configuration.getWorkers().size();
        thread_count = receiver_count + worker_count;
        threads = std::make_unique<std::thread[]>(thread_count);

        uint32_t thread_id = 0;

        for (uint32_t i = 0; i < receiver_count; i++) {
            threads[thread_id] = std::thread(&Queue::receiver_executor, this, configuration.getReceivers()[i], i);
            bind_to_processor(&threads[thread_id], configuration.getReceivers()[i]);
            thread_id++;
        }

        for (auto worker : configuration.getWorkers()) {
            threads[thread_id] = std::thread(&Queue::worker_executor, this, worker);
            bind_to_processor(&threads[thread_id], worker);
            thread_id++;
        }
    } else if (configuration.getReceiverCount() > 0 && configuration.getWorkerCount() > 0) {
        receiver_count = configuration.getReceiverCount();
        worker_count = configuration.getWorkerCount();
        thread_count = receiver_count + worker_count;
        threads = std::make_unique<std::thread[]>(thread_count);

        for (uint32_t i = 0; i < configuration.getReceiverCount(); i++) {
            threads[i] = std::thread(&Queue::receiver_executor, this, i % processor_count, i);
            bind_to_processor(&threads[i], i % processor_count);
        }

        for (uint32_t i = configuration.getReceiverCount(); i < thread_count; i++) {
            threads[i] = std::thread(&Queue::worker_executor, this, i % processor_count);
            bind_to_processor(&threads[i], i % processor_count);
        }
    } else {
        if (processor_count > 1) {
            thread_count = processor_count;
            threads = std::make_unique<std::thread[]>(processor_count);
            receiver_count = processor_count / 4;

            if (receiver_count == 0) {
                receiver_count = 1;
            }

            worker_count = thread_count - receiver_count;

            for (uint32_t i = 0; i < processor_count; i++) {
                if (i < receiver_count) {
                    threads[i] = std::thread(&Queue::receiver_executor, this, i, i);
                } else {
                    threads[i] = std::thread(&Queue::worker_executor, this, i);
                }

                bind_to_processor(&threads[i], i);
            }
        } else {
            thread_count = 2;
            receiver_count = 1;
            worker_count = 1;
            threads = std::make_unique<std::thread[]>(thread_count);
            threads[0] = std::thread(&Queue::receiver_executor, this, 0, 0);
            threads[1] = std::thread(&Queue::worker_executor, this, 0);
        }
    }

    task_counters.clear();
    queue_mutexes.clear();
    task_queues = std::make_unique<std::queue<std::unique_ptr<Task> >[]>(receiver_count);

    for (uint32_t i = 0; i < receiver_count; i++) {
        task_counters.push_back(0);
        std::array<int, 2> arr = {0, 0};
        signalPipes.emplace_back(arr);
        queue_mutexes.push_back(std::move(std::make_unique<std::mutex>()));
    }

    std::unique_lock<std::mutex> lock{queue_init_mutex};
    is_queue_init_complete = true;
    queue_init_condition.notify_all();
}

void Queue::bind_to_processor(std::thread *thread, uint16_t processor) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(processor, &cpuset);

    int rc = pthread_setaffinity_np(thread->native_handle(), sizeof(cpu_set_t), &cpuset);

    if (rc != 0) {
        /* Non-fatal issue */
        syslog(LOG_ERR, "Could not set affinity for processor: %u", processor);
    }
}

auto Queue::bind_to_socket(uint16_t port, uint16_t processor) -> int    {
    int server_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    if (-1 == server_socket) {
        syslog(LOG_ERR, "Couldn't create socket on processor %u", processor);
        return -1;
    }

    int optval = 1;

    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &optval, sizeof(optval)) == -1) {
        syslog(LOG_ERR, "Couldn't set socket option for port reuse %s", strerror(errno));
        return -1;
    }

    struct timeval tv {
        0, TASKS_RECEIVE_TIMEOUT
    };

    if (setsockopt(server_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        syslog(LOG_ERR, "Couldn't set socket option for timeout %s", strerror(errno));
        return -1;
    }

    struct sockaddr_in6 server_address {};

    server_address.sin6_family = AF_INET6;

    server_address.sin6_port = htons(port);

    server_address.sin6_addr = in6addr_any;

    if (bind(server_socket, reinterpret_cast<struct sockaddr *>(&server_address), sizeof(sockaddr_in6)) == -1) {
        syslog(LOG_ERR, "Couldn't bind to socket on processor %u: %s", processor, strerror(errno));
        return -1;
    }

    syslog(LOG_INFO, "Started listening on port %u with processor %u", port, processor);

    return server_socket;
}

void Queue::receiver_executor(uint16_t processor, uint16_t id) {
    /* Once the syslog message is printed the signals are already blocked */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &set, nullptr);

    std::unique_lock<std::mutex> lock{queue_init_mutex};

    if (!is_queue_init_complete) {
        queue_init_condition.wait(lock, [this] { return is_queue_init_complete.load(); });
    }

    if (!is_running) {
        return;
    }

    syslog(LOG_INFO, "Receiver thread started on processor %u", processor);

    if (-1 == pipe2(signalPipes[id].data(), O_CLOEXEC)) {
        syslog(LOG_ERR, "Could not create pipe: %s", strerror(errno));
        is_running = false;
        return;
    }

    if (fcntl(signalPipes[id][1], F_SETFL, O_NONBLOCK) == -1) {
        syslog(LOG_ERR, "Could not set pipe to be non-blocking");
        is_running = false;
        return;
    }

    receivers_inited++;

    lock.unlock();

    if (receivers_inited == receiver_count) {
        all_receivers_inited = true;
        availability_condition.notify_all();
    }

    int socket = bind_to_socket(configuration.getPort(), processor);

    if (socket == -1) {
        is_running = false;
        return;
    }

    auto buffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());
    struct sockaddr_in6 sender {};
    socklen_t sender_length{};
    ssize_t receive_length{};
    uint32_t local_receive_count = 0;

    std::queue<std::unique_ptr<Task> > localQueue;

    bool isDiagTimerUsed = configuration.isDiagTimerUsed();

    while (is_running) {
        while (is_running) {
            if (localQueue.size() >= TASKS_ADDED_AT_ONCE) {
                break;
            }

            sender_length = sizeof(sockaddr_in6);

            /* TODO: Non-blocking, busy-wait? */
            receive_length = recvfrom(socket, buffer.get(), configuration.getUdpPayloadSize(), 0, reinterpret_cast<struct sockaddr *>(&sender),
                                      &sender_length);

            if (0 < receive_length) {
                /* As the DNS header is 12 bytes, everything below and erronous packets can be dropped */
                if (DnsMessage::DNS_HEADER_LENGTH > receive_length) {
                    syslog(LOG_DEBUG, "Ignoring frame on processor %u", processor);
                    continue;
                }

                if (Configuration::LogLevel::DEBUG == configuration.getLogLevel()) {
                    syslog(LOG_DEBUG, "Received a frame on processor %u from port %u", processor, htons(sender.sin6_port));
                }

                localQueue.emplace(new Task{configuration, socket, std::move(buffer), sender, sender_length, receive_length});

                /* Avoiding an allocation if timeout occurs during receive */
                buffer = std::make_unique<uint8_t[]>(configuration.getUdpPayloadSize());
            } else {
                if (!localQueue.empty()) {
                    break;
                }
            }
        }

        queue_mutexes[id]->lock();

        int current_task_count = task_counters[id];

        while (!localQueue.empty()) {
            task_queues[id].emplace(std::move(localQueue.front()));
            localQueue.pop();

            ++task_counters[id];

            if (isDiagTimerUsed) {
                ++receive_count;
                ++local_receive_count;
            }
        }

        if (0 == current_task_count) {
            syslog(LOG_DEBUG, "Writing to pipe on processor %u", processor);

            if (0 >= write(signalPipes[id][1], "a", 1)) {
                syslog(LOG_ERR, "Could not write to signal pipe");
                is_running = false;
                queue_mutexes[id]->unlock();
                return;
            }
        }

        queue_mutexes[id]->unlock();
    }

    close(socket);

    if (isDiagTimerUsed) {
        syslog(LOG_ERR, "Received tasks on processor %u: %u (total: %u)", processor, local_receive_count, receive_count);
    }

    syslog(LOG_INFO, "Receiver thread stopped on processor %u", processor);
}

void Queue::worker_executor(uint16_t processor) {
    /* Once the syslog message is printed the signals are already blocked */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &set, nullptr);

    std::unique_lock<std::mutex> lock{running_mutex};

    availability_condition.wait(lock, [this] { return all_receivers_inited.load(); });

    if (!is_running) {
        return;
    }

    std::list<std::unique_ptr<Task> > initialTasks;
    std::map<int, std::unique_ptr<Task> > resolverTasks;

    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);

    struct epoll_event ev {};
    std::array<struct epoll_event, EPOLL_MAX_EVENTS> events{};

    if (epoll_fd == -1) {
        is_running = false;
        syslog(LOG_ERR, "Failed to create epoll file descriptor");
        return;
    }

    int diag_timer_fd{-1};
    uint64_t exp{0};

    if (configuration.isDiagTimerUsed()) {
        diag_timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);

        if (-1 == diag_timer_fd) {
            syslog(LOG_ERR, "Could not create diagnostic timer");
            is_running = false;
            return;
        }

        struct timespec now {};

        clock_gettime(CLOCK_MONOTONIC, &now);

        struct itimerspec new_value {};

        new_value.it_value.tv_sec = now.tv_sec + configuration.getDiagTimerInterval();

        new_value.it_value.tv_nsec = now.tv_nsec;

        new_value.it_interval.tv_sec = configuration.getDiagTimerInterval();

        new_value.it_interval.tv_nsec = 0;

        if (-1 == timerfd_settime(diag_timer_fd, TFD_TIMER_ABSTIME, &new_value, nullptr)) {
            syslog(LOG_DEBUG, "Could not reset timer: %s", strerror(errno));
        }

        ev.events = EPOLLIN;
        ev.data.fd = diag_timer_fd;

        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, diag_timer_fd, &ev) == -1) {
            is_running = false;
            syslog(LOG_ERR, "Could not add diag timer to epoll_ctl: %s", strerror(errno));
            return;
        }
    }

    int central_timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);

    if (-1 == central_timer_fd) {
        syslog(LOG_ERR, "Could not create central timer");
        is_running = false;
        return;
    }

    ev.events = EPOLLIN;
    ev.data.fd = central_timer_fd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, central_timer_fd, &ev) == -1) {
        is_running = false;
        syslog(LOG_ERR, "Could not add central timer to epoll_ctl: %s", strerror(errno));
        return;
    }

    syslog(LOG_INFO, "Worker thread started on processor %u", processor);

    lock.unlock();

    for (uint32_t i = 0; i < receiver_count; i++) {
        ev.events = EPOLLIN;
        ev.data.fd = signalPipes[i][0];

        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, signalPipes[i][0], &ev) == -1) {
            is_running = false;
            syslog(LOG_ERR, "Could not add pipe to epoll_ctl: %s", strerror(errno));
            return;
        }
    }

    /* Only accept new connections if the current ones (query + timer + WORKER_LIMIT_BUFFER for buffer) do not exceed the worker limit */
    rlim_t workerLimit = configuration.getFdLimit() / 2 / worker_count - WORKER_LIMIT_BUFFER;

    uint32_t processedCount = 0;
    uint32_t timeoutCount = 0;
    uint32_t maxInitialTaskSize = 0;
    uint32_t maxResolverTaskSize = 0;
    int maxNfds = 0;
    uint32_t eventTimeoutCount = 0;
    uint32_t initTimeoutCount = 0;

    std::vector<Task::timer_guard> guardStorage;
    guardStorage.reserve(TIMER_QUEUE_INITIAL_CAPACITY);
    Task::timer_queue timerQueue(Task::greaterComparator(), std::move(guardStorage));
    char pipeBuffer{};
    std::vector<bool> isDataInPipes;
    bool atLeastOnePipeActive = false;
    bool pipeActivatedInThisCycle = false;

    for (uint32_t i = 0; i < receiver_count; i++) {
        isDataInPipes.push_back(false);
    }

    bool isTimeoutOccuring = false;
    uint16_t burstLimiter = 0;
    bool isDiagTimerUsed = configuration.isDiagTimerUsed();
    uint16_t currentReceiver = 0;

    while (is_running) {
        int nfds = epoll_wait(epoll_fd, events.begin(), EPOLL_MAX_EVENTS, EPOLL_TIMEOUT);

        if (nfds == -1) {
            is_running = false;
            syslog(LOG_ERR, "Could not execute epoll_wait");
            return;
        }

        if (isDiagTimerUsed) {
            if (nfds > maxNfds) {
                maxNfds = nfds;
            }

            if (resolverTasks.size() > maxResolverTaskSize) {
                maxResolverTaskSize = resolverTasks.size();
            }
        }

        for (uint32_t i = 0; i < receiver_count; i++) {
            isDataInPipes[i] = false;
        }

        isTimeoutOccuring = false;

        for (int n = 0; n < nfds; ++n) {
            int eventfd = events[n].data.fd;

            if (-1 == eventfd) {
                continue;
            }

            if (diag_timer_fd != eventfd) {
                syslog(LOG_DEBUG, "Event triggered: %d on processor %u", eventfd, processor);
            }

            if (isDiagTimerUsed) {
                if (diag_timer_fd == eventfd) {
                    if (-1 == read(diag_timer_fd, &exp, sizeof(uint64_t))) {
                        syslog(LOG_ERR, "Could not read from the diagnostic timer");
                    }

                    std::lock_guard<std::mutex> lock{running_mutex};

                    if (maxNfds > 1) {
                        syslog(LOG_ERR, "Diag timer (%02u): maxnfds: %d, proc: %u, inittmo: %u, eventtmo: %u, tmo: %u, pend: %u, init: %lu, res: %lu, maxinit: %u, maxres: %u", processor, maxNfds, processedCount, initTimeoutCount, eventTimeoutCount, timeoutCount, receive_count - processedCount, initialTasks.size(), resolverTasks.size(), maxInitialTaskSize, maxResolverTaskSize);
                    }

                    processedCount = 0;
                    initTimeoutCount = 0;
                    eventTimeoutCount = 0;
                    timeoutCount = 0;
                    maxNfds = 0;
                    maxInitialTaskSize = 0;
                    maxResolverTaskSize = 0;

                    continue;
                }
            }

            if (central_timer_fd == eventfd) {
                isTimeoutOccuring = true;
                continue;
            }

            for (uint32_t i = 0; i < receiver_count; i++) {
                if (signalPipes[i][0] == eventfd) {
                    isDataInPipes[i] = true;
                    atLeastOnePipeActive = true;
                    pipeActivatedInThisCycle = true;
                    break;
                }
            }

            if (pipeActivatedInThisCycle) {
                pipeActivatedInThisCycle = false;
                continue;
            }

            auto taskIterator = resolverTasks.find(eventfd);

            if (taskIterator != resolverTasks.end()) {
                auto &task = taskIterator->second;

                task->handleStateWrapper();

                if (TaskState::FINISHED == task->getState()) {
                    /* TODO: The initial tasks can be iterated here to handle a createSocket if socket exhaustion is a problem */
                    if (isDiagTimerUsed) {
                        ++processedCount;
                    }

                    task->invalidateTimer();
                    resolverTasks.erase(task->getSocket());
                }
            } else {
                setlogmask (LOG_UPTO (LOG_DEBUG));
                syslog(LOG_ERR, "Stray socket (proc %u, no %d from %d): %d", processor, n + 1, nfds, eventfd);

                for (int no = 0; no < nfds; ++no) {
                    syslog(LOG_ERR, "events: %d", events[no].data.fd);
                }

                is_running = false;
                return;
            }
        }

        if (atLeastOnePipeActive && initialTasks.size() + resolverTasks.size() < workerLimit) {
            bool avoidsBurst = true;

            if (!isDataInPipes[currentReceiver]) {
                currentReceiver++;

                if (currentReceiver == receiver_count) {
                    currentReceiver = 0;
                    avoidsBurst = false;
                }
            }

            if (burstLimiter < BURST_LIMIT) {
                burstLimiter++;
                avoidsBurst = false;
            } else {
                burstLimiter = 0;
            }

            if (avoidsBurst) {
                rlim_t effectiveLimit = workerLimit - (initialTasks.size() + resolverTasks.size());
                rlim_t removedTasks = TASKS_REMOVED_AT_ONCE;

                std::lock_guard<std::mutex> lock{*queue_mutexes[currentReceiver]};

                int current_task_count = task_counters[currentReceiver];

                if (removedTasks > effectiveLimit) {
                    removedTasks = effectiveLimit;
                }

                if (removedTasks > task_counters[currentReceiver]) {
                    removedTasks = task_counters[currentReceiver];
                }

                for (rlim_t i = 0; i < removedTasks; i++) {
                    syslog(LOG_DEBUG, "Task executing on processor %u", processor);
                    initialTasks.emplace_back(std::move(task_queues[currentReceiver].front()));
                    task_queues[currentReceiver].pop();
                    --task_counters[currentReceiver];
                }

                if (removedTasks > 0 && 0 < current_task_count && 0 == task_counters[currentReceiver]) {
                    if (-1 == read(signalPipes[currentReceiver][0], &pipeBuffer, 1)) {
                        syslog(LOG_ERR, "Error during pipe read: %s", strerror(errno));
                        is_running = false;
                        return;
                    }
                }

                currentReceiver++;

                if (currentReceiver == receiver_count) {
                    currentReceiver = 0;
                }
            }
        }

        if (isTimeoutOccuring) {
            /* TODO: Multiple reads at once */
            if (-1 == read(central_timer_fd, &exp, sizeof(uint64_t))) {
                syslog(LOG_ERR, "Could not read from the central timer");
            }

            Task::timer_guard timerGuard = timerQueue.top();
            Task *taskPointer{nullptr};
            bool wasTaskProcessed = false;

            while (!timerQueue.empty()) {
                timerGuard = timerQueue.top();
                taskPointer = *timerGuard;

                if (taskPointer == nullptr) {
                    timerQueue.pop();
                    wasTaskProcessed = true;
                    continue;
                }

                int taskSocket = taskPointer->getSocket();

                if (TaskState::FINISHED == taskPointer->getState()) {
                    if (0 == taskPointer->getRemainingTimeouts()) {
                        resolverTasks.erase(taskSocket);
                    }

                    timerQueue.pop();
                    wasTaskProcessed = true;
                    continue;
                }

                auto taskIterator = resolverTasks.find(taskSocket);

                if (taskIterator != resolverTasks.end()) {
                    if (wasTaskProcessed) {
                        break;
                    }

                    if (configuration.getAttempts() > 1 || configuration.getExternalResolvers().size() > 1) {
                        auto &task = taskIterator->second;

                        if (TaskState::RECEIVE_PACKET == task->getState()) {
                            if (isDiagTimerUsed) {
                                timeoutCount++;
                            }

                            syslog(LOG_DEBUG, "Timeout occured when listening for response");
                            task->setState(TaskState::NEXT_RESOLVER);
                            task->setTimerArmState(false);

                            if (!task->resetElapsedTime()) {
                                is_running = false;
                                return;
                            }

                            initialTasks.push_back(std::move(task));
                        } else if (TaskState::SEND_PACKET == task->getState()) {
                            if (isDiagTimerUsed) {
                                timeoutCount++;
                            }

                            syslog(LOG_DEBUG, "Timeout occured when sending to %s", task->getCurrentQr() == DnsMessage::QrType::REQUEST ? "resolver" : "client");

                            if (DnsMessage::QrType::REQUEST == task->getCurrentQr()) {
                                task->setState(TaskState::NEXT_RESOLVER);
                                task->setTimerArmState(false);

                                if (!task->resetElapsedTime()) {
                                    is_running = false;
                                    return;
                                }

                                initialTasks.push_back(std::move(task));
                            }
                        }
                    }

                    if (TaskState::NEXT_RESOLVER != taskPointer->getState()) {
                        taskPointer->setState(TaskState::FINISHED);
                    }

                    taskPointer->invalidateTimer();

                    resolverTasks.erase(taskSocket);
                    timerQueue.pop();

                    continue;
                }

                if (isDiagTimerUsed) {
                    eventTimeoutCount++;
                }

                syslog(LOG_DEBUG, "Removing task from initial tasks");
                taskPointer->setState(TaskState::FINISHED);
                timerQueue.pop();
                wasTaskProcessed = true;
            }

            if (!timerQueue.empty()) {
                Task *task = *timerQueue.top();

                auto resultTime = task->getStartTime() + std::chrono::milliseconds(configuration.getTimeout());
                auto secs = std::chrono::time_point_cast<std::chrono::seconds>(resultTime);
                auto ns = std::chrono::time_point_cast<std::chrono::nanoseconds>(resultTime) - std::chrono::time_point_cast<std::chrono::nanoseconds>(secs);

                struct itimerspec new_value {};

                new_value.it_value.tv_sec = secs.time_since_epoch().count();
                new_value.it_value.tv_nsec = ns.count();

                if (-1 == timerfd_settime(central_timer_fd, TFD_TIMER_ABSTIME, &new_value, nullptr)) {
                    syslog(LOG_DEBUG, "Could not reset timer: %s", strerror(errno));
                    is_running = false;
                    return;
                }
            }
        }

        if (isDiagTimerUsed) {
            if (initialTasks.size() > maxInitialTaskSize) {
                maxInitialTaskSize = initialTasks.size();
            }
        }

        auto iter = initialTasks.begin();

        while (iter != initialTasks.end()) {
            auto &task = *iter;

            if (task->getElapsedTime() >= configuration.getTimeout()) {
                task->setState(TaskState::NEXT_RESOLVER);
            }

            task->handleStateWrapper();

            if (TaskState::FINISHED == task->getState()) {
                if (isDiagTimerUsed) {
                    ++initTimeoutCount;
                }

                initialTasks.erase(iter++);
                continue;
            }

            if (-1 != task->getSocket()) {
                struct epoll_event ev {};

                if (!task->getTimerArmState()) {
                    task->setTimerQueue(&timerQueue);
                    task->setCentralSocket(central_timer_fd);

                    if (timerQueue.empty()) {
                        auto resultTime = task->getStartTime() + std::chrono::milliseconds(configuration.getTimeout());
                        auto secs = std::chrono::time_point_cast<std::chrono::seconds>(resultTime);
                        auto ns = std::chrono::time_point_cast<std::chrono::nanoseconds>(resultTime) - std::chrono::time_point_cast<std::chrono::nanoseconds>(secs);

                        struct itimerspec new_value {};

                        new_value.it_value.tv_sec = secs.time_since_epoch().count();
                        new_value.it_value.tv_nsec = ns.count();

                        if (-1 == timerfd_settime(central_timer_fd, TFD_TIMER_ABSTIME, &new_value, nullptr)) {
                            syslog(LOG_DEBUG, "Could not reset timer: %s", strerror(errno));
                            is_running = false;
                            return;
                        }
                    }

                    task->setTimerArmState(true);
                    task->incrementRemainingTimeouts();

                    auto timerGuard = std::make_shared<Task *>(task.get());

                    task->setTimerGuard(timerGuard);

                    timerQueue.emplace(timerGuard);
                }

                ev.events = EPOLLIN;
                ev.data.fd = task->getSocket();

                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, task->getSocket(), &ev) == -1) {
                    is_running = false;
                    syslog(LOG_ERR, "Could not add socket to epoll_ctl: %s", strerror(errno));
                    return;
                }

                syslog(LOG_DEBUG, "Added a new socket identifier to the epoll queue: %d", ev.data.fd);

                resolverTasks[task->getSocket()] = std::move(task);
                initialTasks.erase(iter++);
                continue;
            }

            ++iter;
        }
    }

    if (0 != close(epoll_fd)) {
        syslog(LOG_ERR, "Failed to close epoll file descriptor");
    }

    syslog(LOG_INFO, "Worker thread stopped on processor %u", processor);
}