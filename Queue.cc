#include "Queue.h"

#include "Configuration.h"
#include "DnsMessage.h"

#include <cerrno>
#include <cstring>
#include <list>
#include <signal.h>
#include <syslog.h>

Queue::Queue(const Configuration &configuration) : configuration(configuration) {
}

void Queue::init() {
    is_running = true;

    if (!configuration.getReceivers().empty() && !configuration.getWorkers().empty()) {
        thread_count = configuration.getReceivers().size() + configuration.getWorkers().size();
        threads.reset(new std::thread[thread_count]);

        uint32_t thread_id = 0;

        for (auto receiver : configuration.getReceivers()) {
            threads[thread_id] = std::thread(&Queue::receiver_executor, this, receiver);
            bind_to_processor(&threads[thread_id], receiver);
            thread_id++;
        }

        for (auto worker : configuration.getWorkers()) {
            threads[thread_id] = std::thread(&Queue::worker_executor, this, worker);
            bind_to_processor(&threads[thread_id], worker);
            thread_id++;
        }
    } else if (configuration.getReceiverCount() > 0 && configuration.getWorkerCount() > 0) {
        thread_count = configuration.getReceiverCount() + configuration.getWorkerCount();
        threads.reset(new std::thread[thread_count]);

        for (uint32_t i = 0; i < configuration.getReceiverCount(); i++) {
            threads[i] = std::thread(&Queue::receiver_executor, this, i);
            bind_to_processor(&threads[i], i % processor_count);
        }

        for (uint32_t i = configuration.getReceiverCount(); i < thread_count; i++) {
            threads[i] = std::thread(&Queue::worker_executor, this, i);
            bind_to_processor(&threads[i], i % processor_count);
        }
    } else {
        if (processor_count > 1) {
            thread_count = processor_count;
            threads.reset(new std::thread[processor_count]);
            uint32_t receiver_count = processor_count / 4;

            if (receiver_count == 0) {
                receiver_count = 1;
            }

            for (uint32_t i = 0; i < processor_count; i++) {
                if (i < receiver_count) {
                    threads[i] = std::thread(&Queue::receiver_executor, this, i);
                } else {
                    threads[i] = std::thread(&Queue::worker_executor, this, i);
                }
                bind_to_processor(&threads[i], i);
            }
        } else {
            thread_count = 2;
            threads.reset(new std::thread[thread_count]);
            threads[0] = std::thread(&Queue::receiver_executor, this, 0);
            threads[1] = std::thread(&Queue::worker_executor, this, 0);
        }
    }
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

    struct timeval tv{1, 0};

    if (setsockopt(server_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        syslog(LOG_ERR, "Couldn't set socket option for timeout %s", strerror(errno));
        return -1;
    }

    struct sockaddr_in6 server_address{};
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

void Queue::receiver_executor(uint16_t processor) {
    /* Once the syslog message is printed the signals are already blocked */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    syslog(LOG_INFO, "Receiver thread started on processor %u", processor);

    int socket = bind_to_socket(configuration.getPort(), processor);

    if (socket == -1) {
        is_running = false;
        return;
    }

    while (is_running) {
        std::unique_ptr<uint8_t> buffer(new uint8_t[configuration.getUdpPayloadSize()]);
        struct sockaddr_in6 sender{};
        socklen_t sender_length = sizeof(sockaddr_in6);
        ssize_t receive_length{};

        receive_length = recvfrom(socket, buffer.get(), configuration.getUdpPayloadSize(), 0, reinterpret_cast<struct sockaddr *>(&sender),
				                  &sender_length);
        
        if (-1 == receive_length) {
            continue;
        }

        /* As the DNS header is 12 bytes, everything below and erronous packets can be dropped */
        if (DNS_HEADER_LENGTH > receive_length) {
            syslog(LOG_DEBUG, "Ignoring frame on processor %u", processor);
            continue;
        }
        
        syslog(LOG_DEBUG, "Received a frame on processor %u from port %u", processor, htons(sender.sin6_port));

        std::lock_guard<std::mutex> lock{queue_mutex};
        ++task_count;
        task_queue.emplace(new Task{configuration, socket, std::move(buffer), sender, sender_length, receive_length});
        availability_condition.notify_all();
    }

    close(socket);

    syslog(LOG_INFO, "Receiver thread stopped on processor %u", processor);
}

void Queue::worker_executor(uint16_t processor) {
    /* Once the syslog message is printed the signals are already blocked */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    syslog(LOG_INFO, "Worker thread started on processor %u", processor);

    std::list<std::unique_ptr<Task> > tasks;

    while (is_running) {
        std::unique_ptr<Task> task;

        bool isReturningTask = remove(tasks.size(), task);

        if (isReturningTask) {
            task->setProcessor(processor);
            tasks.push_back(std::move(task));
        }

        std::for_each(tasks.begin(), tasks.end(), [](const auto &task){ auto state = task->getState(); task->stateHandler(); if (task->getState() != state) {task->printState();} });

        tasks.remove_if([](auto const & p) { return p->getState() == TaskState::FINISHED; });
    }

    syslog(LOG_INFO, "Worker thread stopped on processor %u", processor);
}

auto Queue::remove(size_t pendingAnswers, std::unique_ptr<Task> &task) -> bool {
    bool isReturningTask = false;

    std::unique_lock<std::mutex> lock{queue_mutex};

    if (task_queue.empty() && pendingAnswers == 0) {
        availability_condition.wait(lock, [this] { return !task_queue.empty() || !is_running; });
    }

    if (!is_running) {
        return false;
    }

    if (!task_queue.empty()) {
        task = std::move(task_queue.front());
        task_queue.pop();
        isReturningTask = true;
        --task_count;
    }

    lock.unlock();

    return isReturningTask;
}
