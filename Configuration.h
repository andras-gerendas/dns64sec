#pragma once

#include <arpa/inet.h>
#include <string>
#include <string_view>
#include <vector>

constexpr auto DNS_PORT = 53;
constexpr auto wellKnownPrefixString = "64:ff9b::/96";

class Configuration {
        uint16_t attempts{3};
        std::string configFile{"/etc/dns64sec.conf"};
        std::string prefixString{wellKnownPrefixString};
        bool isWellKnownB{false};
        struct in6_addr prefix{};
        uint8_t prefixLength{96};
        std::string resolverConfig{"/etc/resolv.conf"};
        bool enforceDnssec{false};
        bool ignoreResolverConfig{false};
        bool removeDnssecRrs{false};
        bool validateDnssec{false};
        std::vector<struct sockaddr_storage> externalResolvers;
        std::vector<struct sockaddr_storage> trustedResolvers;
        size_t receiverCount{0};
        size_t workerCount{0};
        std::vector<uint16_t> receivers;
        std::vector<uint16_t> workers;
        uint16_t resolverPort{DNS_PORT};
        uint16_t port{DNS_PORT};
        uint16_t timeout{5000};
        uint16_t udpPayloadSize{512};

        void addResolver(const std::string &resolver);
        auto loadConfigurationFromFile(std::ifstream &fileStream, std::vector<std::string> &resolverStrings) -> bool;
        auto loadResolversFromFile(std::vector<std::string> &resolverStrings) -> bool;
        static auto parseLine(const std::string_view &haystack, const std::string_view &needle, bool *isFound = nullptr, bool hasColon = true) -> std::string;
        void parseResolverLine(std::vector<std::string> &resolverStrings, const std::string_view &line);
        auto parseSpecifierLine(std::vector<uint16_t> &specifiers, const std::string_view &line, const std::string &needle) -> bool;
        auto validateBoolean(const std::string_view &haystack, const std::string &optionName, bool &resultValue, bool *isFound = nullptr) -> bool;
        template<class T>
        auto validateInteger(const std::string_view &haystack, const std::string &optionName, T &resultValue, uint32_t low = 1, uint32_t high = static_cast<uint16_t>(UINT16_MAX)) -> bool;

    public:

        auto loadConfiguration() -> bool;

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

        [[nodiscard]] auto getTimeout() const -> uint16_t {
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
};