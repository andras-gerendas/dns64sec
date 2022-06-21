/**
 * @file Configuration.h
 * @author Andras Attila Gerendas
 * @brief Configuration handling class
 * @version 0.1
 * @date 2022-06-21
 *
 * @copyright Copyright (c) 2022
 *
 */

#pragma once

#include <arpa/inet.h>
#include <chrono>
#include <string>
#include <string_view>
#include <sys/resource.h>
#include <vector>

class Configuration {
    public:
        /**
         * @brief Logging level of the program
         *
         */
        enum class LogLevel {
            ERR,
            WARN,
            INFO,
            DEBUG
        };

        /**
         * @brief The maximum size of non-EDNS packets
         *
         */
        static inline constexpr uint16_t MAX_NON_EDNS_PACKET = 512U;
    private:
        /**
         * @brief The default file descriptor limit to be used as maximum file descriptor count
         *
         */
        static inline constexpr uint16_t ARG_DEFAULT_FD_LIMIT = 1024U;

        /**
         * @brief The length of the prefix used by default by the program
         *
         */
        static inline constexpr uint8_t ARG_DEFAULT_PREFIX_LEN = 96U;

        /**
         * @brief The default DNS port used by the program
         *
         */
        static inline constexpr uint16_t ARG_DEFAULT_DNS_PORT = 53U;

        /**
         * @brief The well-known DNS64 prefix represented in string form
         *
         */
        static inline constexpr const char * wellKnownPrefixString = "64:ff9b::/96";

        /**
         * @brief The minimum timeout waiting for resolvers to answer
         *
         */
        static inline constexpr uint16_t ARG_MIN_TIMEOUT = 1000U;

        /**
         * @brief The default timeout waiting for resolvers to answer
         *
         */
        static inline constexpr uint16_t ARG_DEFAULT_TIMEOUT = 5000U;

        /**
         * @brief The maximum timeout waiting for resolvers to answer
         *
         */
        static inline constexpr uint16_t ARG_MAX_TIMEOUT = 60000U;

        /**
         * @brief The minimum number of attempts a resolver is attempted
         *
         */
        static inline constexpr uint16_t ARG_MIN_ATTEMPTS = 1U;

        /**
         * @brief The default number of attempts a resolver is attempted
         *
         */
        static inline constexpr uint16_t ARG_DEFAULT_ATTEMPTS = 3U;

        /**
         * @brief The maximum number of attempts a resolver is attempted
         *
         */
        static inline constexpr uint16_t ARG_MAX_ATTEMPTS = 10U;

        /**
         * @brief Base 10 of integers used during parsing (stored as convenience)
         *
         */
        static inline constexpr uint16_t ARG_INT_BASE = 10U;

        /**
         * @brief The number of attempts a resolver is tried before trying the next one
         *
         */
        uint16_t attempts{ARG_DEFAULT_ATTEMPTS};

        /**
         * @brief The configuration file the configuration is loaded from
         *
         */
        std::string configFile{"/etc/dns64sec.conf"};

        /**
         * @brief The prefix string used to calculate the prefix from
         *
         */
        std::string prefixString{wellKnownPrefixString};

        /**
         * @brief Whether the used prefix is the well-known prefix
         *
         */
        bool isWellKnownB{false};

        /**
         * @brief The DNS64 prefix in binary form (parsed from the prefixString)
         *
         */
        struct in6_addr prefix {};

        /**
         * @brief The length of the used prefix
         *
         */
        uint8_t prefixLength{ARG_DEFAULT_PREFIX_LEN};

        /**
         * @brief The name of the configuration file containing the resolvers in resolv.conf format
         *
         */
        std::string resolverConfig{"/etc/resolv.conf"};

        /**
         * @brief Whether DNSSEC validation is performed even if an OPT record with the DO bit set is not received from the client
         *
         */
        bool enforceDnssec{false};

        /**
         * @brief Whether the resolver configuration file is ignored (whether the DNS server addresses are extracted from it)
         *
         */
        bool ignoreResolverConfig{false};

        /**
         * @brief Whether DNSSEC related RRs are removed for synthesized answers even towards clients having the DO bit set
         *
         */
        bool removeDnssecRrs{false};

        /**
         * @brief Whether DNSSEC validation is enabled
         *
         */
        bool validateDnssec{false};

        /**
         * @brief Whether the diagnostic timer is activated
         *
         */
        bool useDiagTimer{false};

        /**
         * @brief The interval in which the diagnostic timer prints the current diagnostic information to syslog
         *
         */
        uint16_t diagTimerInterval{3};

        /**
         * @brief The list of external resolvers used by the program to resolve requests
         *
         */
        std::vector<struct sockaddr_storage> externalResolvers;

        /**
         * @brief The list of trusted resolvers used by the program, to mark resolvers from which DNSSEC answers do not need validation
         *
         */
        std::vector<struct sockaddr_storage> trustedResolvers;

        /**
         * @brief The number of receivers set by the receiver_count option
         *
         */
        size_t receiverCount{0};

        /**
         * @brief The number of workers set by the worker_count option
         *
         */
        size_t workerCount{0};

        /**
         * @brief A list of processors where receivers should be bound
         *
         */
        std::vector<uint16_t> receivers;

        /**
         * @brief A list of processors where workers should be bound
         *
         */
        std::vector<uint16_t> workers;

        /**
         * @brief The port used when communicating with resolvers (for testing purposes)
         *
         */
        uint16_t resolverPort{ARG_DEFAULT_DNS_PORT};

        /**
         * @brief The port used by the program to listen on
         *
         */
        uint16_t port{ARG_DEFAULT_DNS_PORT};

        /**
         * @brief The amount of milliseconds before a next attempt or next resolver is tried, or the handling is finished
         *
         */
        std::chrono::milliseconds timeout{ARG_DEFAULT_TIMEOUT};

        /**
         * @brief The maximum EDNS packet size forwarded in the UDP payload size EDNS option (sets the size of the internal buffer as well)
         *
         */
        uint16_t udpPayloadSize{MAX_NON_EDNS_PACKET};

        /**
         * @brief The current logging level of the program
         *
         */
        LogLevel logLevel{LogLevel::ERR};

        /**
         * @brief The maximum number of file descriptors the program can use to resolve requests
         *
         */
        rlim_t fdLimit{ARG_DEFAULT_FD_LIMIT};

        /**
         * @brief Attempts to convert the textual representation of a resolver to the sockaddr structure, storing it as an external resolver
         *
         * @param resolver The IPv4 or IPv6 address of a resolver
         */
        void addResolver(const std::string &resolver);

        /**
         * @brief Parses the already opened configuration file, line by line
         *
         * @param fileStream The already opened configuration file object
         * @param resolverStrings The temporary list of resolver strings appended by the function
         * @return true The configuration was successfully loaded
         * @return false There was an issue during the parsing of one of the configuration lines
         */
        auto loadConfigurationFromFile(std::ifstream &fileStream, std::vector<std::string> &resolverStrings) -> bool;

        /**
         * @brief Loads the resolvers according to the resolv.conf format
         *
         * @param resolverStrings The temporary list of resolver strings appended by the function
         * @return true The resolvers could be loaded from the file
         * @return false There was an issue during parsing of the file or there are no resolvers added
         */
        auto loadResolversFromFile(std::vector<std::string> &resolverStrings) -> bool;

        /**
         * @brief Attempts to parse the value of a configuration option line as a string
         *
         * @param haystack The complete line the option is searched in
         * @param needle The name of the option being located
         * @param isFound Returns whether a match was found if the address is not a nullptr
         * @param hasColon Whether a colon should be appended to the end of the needle before looking for it
         * @return std::string The value of the option as a string if a match is found, an empty string otherwise
         */
        static auto parseLine(const std::string_view &haystack, const std::string_view &needle, bool *isFound = nullptr, bool hasColon = true) -> std::string;

        /**
         * @brief Extracts the IPv4/IPv6 addresses of resolvers into the resolver strings parameter from the line
         *
         * @param resolverStrings The temporary list of resolver strings appended by the function
         * @param line The complete line the option is searched in
         */
        static void parseResolverLine(std::vector<std::string> &resolverStrings, const std::string_view &line);

        /**
         * @brief Extracts the processor identifiers from the line into the specifiers parameter from the needle option
         *
         * @param specifiers The list of specifiers waiting to be appended by the function
         * @param line The complete line the option is searched in
         * @param needle The name of the option being located
         * @return true The specifiers were successfully extracted, or the option was not found
         * @return false One of the values is outside of the available processor range
         */
        auto parseSpecifierLine(std::vector<uint16_t> &specifiers, const std::string_view &line, const std::string &needle) -> bool;

        /**
         * @brief Extracts the boolean value from the line into the result value parameter
         *
         * @param haystack The complete line the option is searched in
         * @param optionName The name of the option being located
         * @param resultValue The variable where the result will be stored by the function
         * @param isFound Returns whether a match was found if the address is not a nullptr
         * @return true The boolean could be successfully extracted, or the option was not found
         * @return false The option was found, but it could not be parsed as a boolean
         */
        static auto validateBoolean(const std::string_view &haystack, const std::string &optionName, bool &resultValue, bool *isFound = nullptr) -> bool;

        /**
         * @brief Extracts the templated integer value from the line into the result value parameter
         *
         * @tparam T The type of integer to be retrieved
         * @param haystack The complete line the option is searched in
         * @param optionName The name of the option being located
         * @param resultValue The variable where the result will be stored by the function
         * @param low The lower (inclusive) end of the accepted range of the value
         * @param high The higher (inclusive) end of the accepted range of the value
         * @param isFound Returns whether a match was found if the address is not a nullptr
         * @return true The integer could be successfully extracted, or the option was not found
         * @return false The option was found, but it could not be parsed as a valid integer or it was outside of the specified range
         */
        template<class T>
        auto validateInteger(const std::string_view &haystack, const std::string &optionName, T &resultValue, uint32_t low = 1, uint32_t high = static_cast<uint16_t>(UINT16_MAX), bool *isFound = nullptr) -> bool;

    public:
        /**
         * @brief Loads the configuration into the member variables.
         *
         * @return true The configuration was successfully loaded, or the default configuration is applied.
         * @return false There was an issue, which prevents going with the default configuration
         */
        auto loadConfiguration() -> bool;

        /**
         * @brief Restores the configuration to the default state, except the configuration file setting
         *
         */
        void resetConfiguration();

        [[nodiscard]] auto getLogLevel() const -> LogLevel {
            return logLevel;
        }

        [[nodiscard]] auto getPrefix() const -> const struct in6_addr& {
            return prefix;
        }

        [[nodiscard]] auto getPrefixLength() const -> uint8_t {
            return prefixLength;
        }

        [[nodiscard]] auto getExternalResolvers() const -> const std::vector<struct sockaddr_storage>& {
            return externalResolvers;
        }

        [[nodiscard]] auto getTrustedResolvers() const -> const std::vector<struct sockaddr_storage>& {
            return trustedResolvers;
        }

        [[nodiscard]] auto getReceiverCount() const -> size_t {
            return receiverCount;
        }

        [[nodiscard]] auto getWorkerCount() const -> size_t {
            return workerCount;
        }

        [[nodiscard]] auto getReceivers() const -> const std::vector<uint16_t>& {
            return receivers;
        }

        [[nodiscard]] auto getWorkers() const -> const std::vector<uint16_t>& {
            return workers;
        }

        [[nodiscard]] auto getPort() const -> uint16_t {
            return port;
        }

        [[nodiscard]] auto getResolverPort() const -> uint16_t {
            return resolverPort;
        }

        [[nodiscard]] auto getAttempts() const -> uint16_t {
            return attempts;
        }

        [[nodiscard]] auto getTimeout() const -> std::chrono::milliseconds {
            return timeout;
        }

        [[nodiscard]] auto getUdpPayloadSize() const -> uint16_t {
            return udpPayloadSize;
        }

        [[nodiscard]] auto isDnssecEnforced() const -> bool {
            return enforceDnssec;
        }

        [[nodiscard]] auto isDnssecValidated() const -> bool {
            return validateDnssec;
        }

        [[nodiscard]] auto isDiagTimerUsed() const -> bool {
            return useDiagTimer;
        }

        [[nodiscard]] auto getDiagTimerInterval() const -> uint16_t {
            return diagTimerInterval;
        }

        [[nodiscard]] auto isWellKnown() const -> bool {
            return isWellKnownB;
        }

        [[nodiscard]] auto shouldRemoveDnssecRrs() const -> bool {
            return removeDnssecRrs;
        }

        void setConfigFile(const std::string& configFile) {
            this->configFile = configFile;
        }

        void setConfigFile(std::string&& configFile) {
            this->configFile = std::move(configFile);
        }

        [[nodiscard]] auto getFdLimit() const -> rlim_t {
            return fdLimit;
        }

        void setFdLimit(rlim_t fdLimit) {
            this->fdLimit = fdLimit;
        }
};