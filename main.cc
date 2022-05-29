#include "Configuration.h"
#include "Queue.h"

#include <cctype>
#include <csignal>
#include <syslog.h>
#include <sys/stat.h>

using namespace std::chrono_literals;

volatile sig_atomic_t signalled = 0;

void signal_handler(int signal) {
    signalled = signal;
}

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

        if (signalled) {
            if (SIGTERM == signalled) {
                syslog(LOG_INFO, "Received SIGTERM, terminating");
                queue.halt();
                break;
            }

            if (SIGHUP == signalled) {
                syslog(LOG_INFO, "Received SIGHUP, reloading configuration");
                queue.halt();

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