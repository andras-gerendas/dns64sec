/**
 * @file main.cc
 * @author Andras Attila Gerendas
 * @brief Main function starting up the queue and handling signals
 * @version 0.1
 * @date 2022-06-21
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "Configuration.h"
#include "Queue.h"

#include <cctype>
#include <csignal>
#include <sys/resource.h>
#include <sys/stat.h>
#include <syslog.h>

using namespace std::chrono_literals;

/**
 * @brief The identifier of the occured signal, or zero if a signal hasn't occured
 *
 */
volatile sig_atomic_t signalled = 0;

void signal_handler(int signal) {
    signalled = signal;
}

/**
 * @brief The main function creates the configuration and the queue, then listens for signals
 *
 */
auto main(int argc, char * argv[]) -> int {
    openlog("dns64sec", LOG_PID | LOG_CONS, LOG_DAEMON);
    setlogmask (LOG_UPTO (LOG_ERR));

    Configuration configuration;

    if (argc > 1) {
        configuration.setConfigFile(argv[1]);
    }

    if (!configuration.loadConfiguration()) {
        return EXIT_FAILURE;
    }

    Queue queue(configuration);

    struct rlimit fileLimit {};

    int result = getrlimit(RLIMIT_NOFILE, &fileLimit);

    if (0 == result) {
        syslog(LOG_INFO, "Current file limit is %lu, maximum is %lu", fileLimit.rlim_cur, fileLimit.rlim_max);

        configuration.setFdLimit(fileLimit.rlim_cur);

        if (fileLimit.rlim_cur != fileLimit.rlim_max) {
            fileLimit.rlim_cur = fileLimit.rlim_max;

            result = setrlimit(RLIMIT_NOFILE, &fileLimit);

            if (-1 == result) {
                syslog(LOG_INFO, "Could not set file number limit");
            } else {
                configuration.setFdLimit(fileLimit.rlim_max);
            }
        }
    }

    queue.init();

    signal(SIGTERM, signal_handler);
    signal(SIGHUP, signal_handler);

    while (true) {
        std::this_thread::sleep_for(1s);

        if (!queue.isRunning()) {
            syslog(LOG_INFO, "One of the threads has terminated the program");
            queue.halt();
            break;
        }

        if (0 != signalled) {
            if (SIGTERM == signalled) {
                syslog(LOG_INFO, "Received SIGTERM, terminating");
                queue.halt();
                break;
            }

            if (SIGHUP == signalled) {
                syslog(LOG_INFO, "Received SIGHUP, reloading configuration");
                queue.halt();

                configuration.resetConfiguration();

                if (!configuration.loadConfiguration()) {
                    syslog(LOG_ERR, "Couldn't reload configuration, terminating");
                    return EXIT_FAILURE;
                }

                queue.init();
            }

            signalled = 0;
        }
    }
}