#pragma once

#include "Task.h"

#include <atomic>
#include <condition_variable>
#include <functional>
#include <iostream>
#include <mutex>
#include <queue>
#include <thread>

class Configuration;

class Queue {
        const Configuration &configuration;
        std::atomic<bool> is_running{false};
        std::condition_variable availability_condition;
        std::mutex queue_mutex;
        uint32_t thread_count{0};
        /* TODO: Should this variable be removed? */
        std::atomic<uint32_t> task_count{0};
        std::queue<std::unique_ptr<Task> > task_queue;
        uint32_t processor_count{std::thread::hardware_concurrency()};
        std::unique_ptr<std::thread[]> threads;

        static void bind_to_processor(std::thread *thread, uint16_t processor);

        auto bind_to_socket(uint16_t port, uint16_t processor) -> int;
        
        void receiver_executor(uint16_t processor);

        void worker_executor(uint16_t processor);

        auto remove(size_t pendingAnswers, std::unique_ptr<Task> &task) -> bool;

    public:
        explicit Queue(const Configuration &configuration);

        void init();

        auto isRunning() const -> bool {
            return is_running;
        }

        void halt() {
            std::unique_lock<std::mutex> lock{queue_mutex};
            is_running = false;
            availability_condition.notify_all();
            lock.unlock();

            for (uint32_t i = 0; i < thread_count; i++) {
                threads[i].join();
            }
        }
};