/**
 * @file Queue.h
 * @author Andras Attila Gerendas
 * @brief Queue handling class (contains receiver and worker thread functions)
 * @version 0.1
 * @date 2022-06-21
 *
 * @copyright Copyright (c) 2022
 *
 */

#pragma once

#include "Task.h"

#include <atomic>
#include <condition_variable>
#include <functional>
#include <iostream>
#include <list>
#include <map>
#include <mutex>
#include <queue>
#include <thread>

class Configuration;

class Queue {
        /**
         * @brief The amount of cycles to wait before tasks are taken from receiver threads by workers
         *
         */
        static inline constexpr uint16_t BURST_LIMIT = 5U;

        /**
         * @brief The amount of events to wait before iterating through them (or timeout)
         *
         */
        static inline constexpr uint16_t EPOLL_MAX_EVENTS = 1000U;

        /**
         * @brief The amount of time to wait before iterating through the events (or max_events)
         *
         */
        static inline constexpr uint16_t EPOLL_TIMEOUT = 10U;

        /**
         * @brief Time to wait for, before tasks are moved to the queue by the receiver (or added_at_once)
         *
         */
        static inline constexpr uint16_t TASKS_RECEIVE_TIMEOUT = 100U;

        /**
         * @brief Tasks to wait for, before they are moved to the queue by the receiver (or timeout)
         *
         */
        static inline constexpr uint16_t TASKS_ADDED_AT_ONCE = 100U;

        /**
         * @brief Tasks removed at once by workers from receivers
         *
         */
        static inline constexpr uint16_t TASKS_REMOVED_AT_ONCE = 10U;

        /**
         * @brief File descriptor buffer to avoid allocating beyond all available file descriptors
         *
         */
        static inline constexpr uint16_t WORKER_LIMIT_BUFFER = 10U;

        /**
         * @brief The capacity to reserve for the vector behind the timer queue at startup (to avoid a burst because of slow initialization)
         *
         */
        static inline constexpr uint32_t TIMER_QUEUE_INITIAL_CAPACITY = 10000U;

        /**
         * @brief The current configuration instance
         *
         */
        const Configuration &configuration;

        /**
         * @brief Whether the queue should currently be running (monitored by all threads including the main thread)
         *
         */
        std::atomic<bool> is_running{false};

        /**
         * @brief Whether the initialization of the queue is complete (to avoid receivers starting up before their structures are allocated)
         *
         */
        std::atomic<bool> is_queue_init_complete{false};

        /**
         * @brief Signals that receivers have initialized and workers can initialize
         *
         */
        std::condition_variable availability_condition;

        /**
         * @brief Signals that the queue has initialized and receivers can initialize
         *
         */
        std::condition_variable queue_init_condition;

        /**
         * @brief Keeping the receivers locked before the queue is initialized
         *
         */
        std::mutex queue_init_mutex;

        /**
         * @brief Keeping the workers locked before the receivers are initialized
         *
         */
        std::mutex running_mutex;

        /**
         * @brief Locking the individual receiver queue before interaction between a receiver and a worker
         *
         */
        std::vector<std::unique_ptr<std::mutex> > queue_mutexes;

        /**
         * @brief The amount of worker threads currently being active
         *
         */
        uint32_t worker_count{0};

        /**
         * @brief The amount of receiver threads currently being active
         *
         */
        uint32_t receiver_count{0};

        /**
         * @brief The amount of threads currently being active (sum of worker and receiver)
         *
         */
        uint32_t thread_count{0};

        /**
         * @brief The amount of receiver threads currently initialized
         *
         */
        std::atomic<uint32_t> receivers_inited{0};

        /**
         * @brief The amount of queries received (used by the diagnostic timer)
         *
         */
        uint32_t receive_count{0};

        /**
         * @brief The amount of tasks currently in the individual receiver queues (used for activating/deactivating the pipe)
         *
         */
        std::vector<uint32_t> task_counters;

        /**
         * @brief The individual task queues of receivers
         *
         */
        std::unique_ptr<std::queue<std::unique_ptr<Task> >[]> task_queues;

        /**
         * @brief The number of available processors in the system
         *
         */
        uint32_t processor_count{std::thread::hardware_concurrency()};

        /**
         * @brief The thread instances currently active
         *
         */
        std::unique_ptr<std::thread[]> threads;

        /**
         * @brief The individual signal pipes of receivers (the workers are subscribed to these)
         *
         */
        std::vector<std::array<int, 2> > signalPipes;

        /**
         * @brief Whether all receivers have been initialized
         *
         */
        std::atomic<bool> all_receivers_inited{false};

        /**
         * @brief Binds the specified thread to the specified processor
         *
         * @param thread The thread to bind
         * @param processor The processor to bind the thread to
         */
        static void bind_to_processor(std::thread *thread, uint16_t processor);

        /**
         * @brief Creates and binds a listening socket to the specified port
         *
         * @param port The socket to listen on
         * @param processor The processor where the binding happens (used for troubleshooting)
         * @return int The socket file descriptor, or -1 on error
         */
        static auto bind_to_socket(uint16_t port, uint16_t processor) -> int;

        /**
         * @brief The thread function of a receiver thread
         *
         * @param processor The processor where the thread is running
         * @param id The identifier of the thread (used for thread-unique variables)
         */
        void receiver_executor(uint16_t processor, uint16_t id);

        /**
         * @brief The thread function of a worker thread
         *
         * @param processor The processor where the thread is running
         */
        void worker_executor(uint16_t processor);

    public:
        explicit Queue(const Configuration &configuration);

        /**
         * @brief Starts up the receiver and worker threads based on the configuration and creates the thread-specific variables
         *
         */
        void init();

        [[nodiscard]] auto isRunning() const -> bool {
            return is_running;
        }

        /**
         * @brief Stops the receiver and worker threads and restores the queue to the initial position (just in case a configuration reload happens)
         *
         */
        void halt() {
            std::unique_lock<std::mutex> lock{running_mutex};
            is_running = false;
            all_receivers_inited = true;
            availability_condition.notify_all();
            lock.unlock();
            std::unique_lock<std::mutex> initLock{queue_init_mutex};
            is_queue_init_complete = true;
            queue_init_condition.notify_all();
            initLock.unlock();

            for (uint32_t i = 0; i < thread_count; i++) {
                threads[i].join();
            }

            all_receivers_inited = false;
            is_queue_init_complete = false;
            receivers_inited = 0U;

            for (uint32_t i = 0; i < receive_count; i++) {
                close(signalPipes[i][0]);
                close(signalPipes[i][1]);

                task_queues[i] = std::queue<std::unique_ptr<Task>>();
                task_counters[i] = 0;
            }
        }
};