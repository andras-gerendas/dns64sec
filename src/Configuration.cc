/**
 * @file Configuration.cc
 * @author Andras Attila Gerendas
 * @brief Configuration handling class
 * @version 0.1
 * @date 2022-06-21
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "Configuration.h"

#include <cctype>
#include <charconv>
#include <cstring>
#include <experimental/iterator>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <syslog.h>
#include <thread>

void Configuration::addResolver(const std::string& resolver) {
    struct sockaddr_storage addr {};

    const char *server_name_c = resolver.c_str();

    if (1 != inet_pton(AF_INET, server_name_c, &(reinterpret_cast<sockaddr_in*>(&addr)->sin_addr))) {
        if (1 != inet_pton(AF_INET6, server_name_c, &(reinterpret_cast<sockaddr_in6*>(&addr)->sin6_addr))) {
            syslog(LOG_INFO, "Address cannot be used as an IPv4/IPv6 address: %s", server_name_c);
            return;
        }

        addr.ss_family = AF_INET6;
        reinterpret_cast<struct sockaddr_in6*>(&addr)->sin6_port = htons(getResolverPort());
    } else {
        addr.ss_family = AF_INET;
        reinterpret_cast<struct sockaddr_in*>(&addr)->sin_port = htons(getResolverPort());
    }

    syslog(LOG_DEBUG, "Parsing config: Added resolver %s", resolver.c_str());

    externalResolvers.emplace_back(addr);
}

auto Configuration::parseLine(const std::string_view &haystack, const std::string_view &needle,  bool *isFound, bool hasColon) -> std::string {
    std::string result;

    std::size_t needle_position = haystack.find(needle);

    /* Needle not in line */
    if (std::string::npos == needle_position) {
        if (nullptr != isFound) {
            *isFound = false;
        }

        return result;
    }

    if (hasColon) {
        /* Colon not located after needle */
        if (haystack[needle_position + needle.size()] != ':') {
            if (nullptr != isFound) {
                *isFound = false;
            }

            return result;
        }

        needle_position++;
    }

    std::size_t comment_position = haystack.find('#');

    /* Needle commented out */
    if (comment_position != std::string::npos && comment_position < needle_position) {
        if (nullptr != isFound) {
            *isFound = false;
        }

        return result;
    }

    if (nullptr != isFound) {
        *isFound = true;
    }

    for (std::size_t i = needle_position + needle.size(); i < haystack.length(); ++i) {
        if (std::isspace(haystack[i]) != 0) {
            /* Trailing space, as we already have the result */
            if (!result.empty()) {
                break;
            }

            continue;
        }

        result.push_back(haystack[i]);
    }

    return result;
}

void Configuration::parseResolverLine(std::vector<std::string> &resolverStrings, const std::string_view &line) {
    constexpr std::string_view needle = "resolvers:";

    std::size_t needle_position = line.find(needle);

    /* Needle not in line */
    if (std::string::npos == needle_position) {
        return;
    }

    std::size_t comment_position = line.find('#');

    /* Needle commented out */
    if (comment_position != std::string::npos && comment_position < needle_position) {
        return;
    }

    std::string result;

    for (std::size_t i = needle_position + needle.size(); i < line.length(); ++i) {
        if (std::isspace(line[i]) != 0 || line[i] == ',') {
            if (!result.empty()) {
                resolverStrings.emplace_back(result);
                result = "";
                continue;
            }

            continue;
        }

        result.push_back(line[i]);
    }

    if (!result.empty()) {
        resolverStrings.emplace_back(result);
    }
}

auto Configuration::parseSpecifierLine(std::vector<uint16_t> &specifiers, const std::string_view &line, const std::string &needle) -> bool {
    std::size_t needle_position = line.find(needle);

    /* Needle not in line */
    if (std::string::npos == needle_position) {
        return true;
    }

    /* Colon not located after needle */
    if (line[needle_position + needle.size()] != ':') {
        return true;
    }

    needle_position++;

    std::size_t comment_position = line.find('#');

    /* Needle commented out */
    if (comment_position != std::string::npos && comment_position < needle_position) {
        return true;
    }

    std::string result;
    auto previousValue = static_cast<uint16_t>(UINT16_MAX);
    auto currentValue = static_cast<uint16_t>(UINT16_MAX);
    bool isInterval = false;

    uint32_t processor_count = std::thread::hardware_concurrency();

    for (std::size_t i = needle_position + needle.size(); i < line.length() + 1; ++i) {
        if (i == line.length() || std::isspace(line[i]) != 0 || line[i] == ',' || line[i] == '-') {
            if (isInterval) {
                previousValue = currentValue;
            }

            if (!result.empty()) {
                long result_int = std::strtol(result.c_str(), nullptr, ARG_INT_BASE);

                if (result_int <= static_cast<uint16_t>(UINT16_MAX) && result_int >= 0) {
                    currentValue = static_cast<uint16_t>(result_int);

                    if (currentValue > processor_count - 1) {
                        return false;
                    }
                }

                result = "";

                if (i < line.length() && line[i] == '-') {
                    isInterval = true;
                    continue;
                }
            }

            if (currentValue < static_cast<uint16_t>(UINT16_MAX)) {
                if (isInterval) {
                    if (previousValue < static_cast<uint16_t>(UINT16_MAX) && currentValue > previousValue) {
                        for (uint16_t i = previousValue; i < currentValue + 1; i++) {
                            if (i > processor_count - 1) {
                                return false;
                            }

                            specifiers.push_back(i);
                        }
                    }

                    isInterval = false;
                    previousValue = static_cast<uint16_t>(UINT16_MAX);
                } else {
                    specifiers.push_back(currentValue);
                }

                currentValue = static_cast<uint16_t>(UINT16_MAX);
            }

            continue;
        }

        if (i < line.length()) {
            result.push_back(line[i]);
        }
    }

    if (LogLevel::DEBUG != logLevel) {
        return true;
    }

    std::stringstream stream;

    std::copy(specifiers.begin(), specifiers.end(), std::experimental::make_ostream_joiner(stream, ", "));

    std::string out = stream.str();

    syslog(LOG_DEBUG, "Parsing config: %s has value(s) [%s]", needle.c_str(), out.c_str());

    return true;
}

auto Configuration::loadResolversFromFile(std::vector<std::string> &resolverStrings) -> bool {
    std::size_t resolverCount = resolverStrings.size();

    std::ifstream dns_server_file(resolverConfig);

    if (!dns_server_file) {
        return false;
    }

    std::string line;
    constexpr std::string_view nameserver = "nameserver";

    while (std::getline(dns_server_file, line)) {
        /* Constant checks: Line starts with comment, or cannot contain 'nameserver' */
        if (line.length() == 0 || '#' == line[0] || line.length() < nameserver.length()) {
            continue;
        }

        resolverStrings.emplace_back(parseLine(line, nameserver, nullptr, false));
    }

    return resolverStrings.size() > resolverCount;
}

auto Configuration::validateBoolean(const std::string_view &haystack, const std::string &optionName, bool &resultValue, bool *isFound) -> bool {
    const std::string result = parseLine(haystack, optionName, isFound);

    if (result.empty()) {
        return true;
    }

    if (result == "true") {
        resultValue = true;
        syslog(LOG_DEBUG, "Parsing config: %s has value true", optionName.c_str());
        return true;
    }

    if (result == "false") {
        resultValue = false;
        syslog(LOG_DEBUG, "Parsing config: %s has value false", optionName.c_str());
        return true;
    }

    syslog(LOG_ERR, "Couldn't parse option %s as a boolean (true/false)", optionName.c_str());

    return false;
}

template<class T>
auto Configuration::validateInteger(const std::string_view &haystack, const std::string &optionName, T &resultValue, uint32_t low, uint32_t high, bool *isFound) -> bool {
    std::string result = parseLine(haystack, optionName, isFound);

    if (result.empty()) {
        return true;
    }

    long result_int = std::strtol(result.c_str(), nullptr, ARG_INT_BASE);

    if (result_int < low || result_int > high) {
        syslog(LOG_ERR, "Couldn't parse option %s, as its out of range (%u-%u inclusive)", optionName.c_str(), low, high);
        return false;
    }

    syslog(LOG_DEBUG, "Parsing config: %s has value %lu", optionName.c_str(), result_int);

    resultValue = result_int;
    return true;
}

auto Configuration::loadConfigurationFromFile(std::ifstream &fileStream, std::vector<std::string> &resolverStrings) -> bool {
    std::string line;

    while (std::getline(fileStream, line)) {
        if (line.length() == 0 || '#' == line[0]) {
            continue;
        }

        std::string result = parseLine(line, "prefix");

        if (!result.empty()) {
            prefixString = result;
        }

        bool isIgnoreFound = false;

        if (!validateBoolean(line, "ignore_resolver_file", ignoreResolverConfig, &isIgnoreFound)) {
            return false;
        }

        /* Avoid a name match */
        if (isIgnoreFound) {
            continue;
        }

        result = parseLine(line, "resolver_file");

        if (!result.empty()) {
            syslog(LOG_DEBUG, "Parsing config: resolver_file has value %s", result.c_str());
            resolverConfig = result;
        }

        if (!validateBoolean(line, "enforce_dnssec", enforceDnssec)) {
            return false;
        }

        if (!validateBoolean(line, "remove_dnssec_rrs", removeDnssecRrs)) {
            return false;
        }

        if (!validateBoolean(line, "validate_dnssec", validateDnssec)) {
            return false;
        }

        isIgnoreFound = false;

        if (!validateBoolean(line, "use_diag_timer", useDiagTimer, &isIgnoreFound)) {
            return false;
        }

        /* Avoid a name match */
        if (isIgnoreFound) {
            continue;
        }

        if (!validateInteger(line, "diag_timer_interval", diagTimerInterval, 1, 60)) {
            return false;
        }

        if (!validateInteger(line, "attempts", attempts, ARG_MIN_ATTEMPTS, ARG_MAX_ATTEMPTS)) {
            return false;
        }

        if (!validateInteger(line, "receiver_count", receiverCount, 1, static_cast<uint32_t>(INT32_MAX))) {
            return false;
        }

        if (!validateInteger(line, "worker_count", workerCount, 1, static_cast<uint32_t>(INT32_MAX))) {
            return false;
        }

        uint16_t timeoutTemp{};
        bool isTimeoutFound = false;

        if (!validateInteger(line, "timeout", timeoutTemp, ARG_MIN_TIMEOUT, ARG_MAX_TIMEOUT, &isTimeoutFound)) {
            return false;
        }

        if (isTimeoutFound) {
            timeout = std::chrono::milliseconds(timeoutTemp);
        }

        if (!validateInteger(line, "udp_payload_size", udpPayloadSize, MAX_NON_EDNS_PACKET)) {
            return false;
        }

        if (!parseSpecifierLine(receivers, line, "receivers")) {
            syslog(LOG_ERR, "Receiver identifiers given need to be less than processor count (%u)", std::thread::hardware_concurrency());
            return false;
        }

        if (!parseSpecifierLine(workers, line, "workers")) {
            syslog(LOG_ERR, "Worker identifiers given need to be less than processor count (%u)", std::thread::hardware_concurrency());
            return false;
        }

        if (!validateInteger(line, "resolver_port", resolverPort)) {
            return false;
        }

        if (!validateInteger(line, "listen_port", port)) {
            return false;
        }

        result = parseLine(line, "logging_level");

        if (!result.empty()) {
            if (result == "debug") {
                logLevel = LogLevel::DEBUG;
                setlogmask (LOG_UPTO (LOG_DEBUG));
            } else if (result == "info") {
                logLevel = LogLevel::INFO;
                setlogmask (LOG_UPTO (LOG_INFO));
            } else if (result == "warn") {
                logLevel = LogLevel::WARN;
                setlogmask (LOG_UPTO (LOG_WARNING));
            } else if (result == "err") {
                logLevel = LogLevel::ERR; /* Needs to be set explicitly just in case a reload changes it */
                setlogmask (LOG_UPTO (LOG_ERR));
            } else {
                syslog(LOG_ERR, "Invalid logging level, possible: debug, info, warn, err");
                return false;
            }

            syslog(LOG_DEBUG, "Parsing config: logging_level has value %s", result.c_str());
        }

        parseResolverLine(resolverStrings, line);
    }

    return true;
}

auto Configuration::loadConfiguration() -> bool {
    std::vector<std::string> resolverStrings;

    std::ifstream config_file(configFile);

    if (!config_file) {
        syslog(LOG_INFO, "Couldn't load configuration file, going with the defaults");
    } else {
        /* Avoid double error message */
        if (!loadConfigurationFromFile(config_file, resolverStrings)) {
            return false;
        }
    }

    /** TODO: This is needed until non-recursion is implemented */
    if (!ignoreResolverConfig && !loadResolversFromFile(resolverStrings)) {
        syslog(LOG_INFO, "Couldn't add external resolvers from resolver file");

        /* Avoid double error message */
        if (resolverStrings.empty()) {
            return false;
        }
    }

    for (const auto &resolver : resolverStrings) {
        addResolver(resolver);
    }

    if (externalResolvers.empty()) {
        syslog(LOG_ERR, "There are no external resolvers to use");
        return false;
    }

    std::istringstream iss(prefixString);

    std::string buffer;

    std::getline(iss, buffer, '/');

    if (1 != inet_pton(AF_INET6, buffer.c_str(), &prefix)) {
        syslog(LOG_ERR, "Couldn't convert user-supplied DNS64 prefix");
        return false;
    }

    std::getline(iss, buffer, '/');

    long pre = std::strtol(buffer.c_str(), nullptr, ARG_INT_BASE);

    if (pre != 96 && pre != 32 && pre != 40 && pre != 48 && pre != 56 && pre != 64) {
        syslog(LOG_ERR, "Invalid prefix length, usable: 32, 40, 48, 56, 64, 96");
        return false;
    }

    prefixLength = pre;

    syslog(LOG_DEBUG, "Parsing config: prefix has value %s", prefixString.c_str());

    if (ARG_DEFAULT_PREFIX_LEN == prefixLength) {
        struct in6_addr wellKnown {};

        std::istringstream iss(wellKnownPrefixString);

        std::getline(iss, buffer, '/');

        if (1 != inet_pton(AF_INET6, buffer.c_str(), &wellKnown)) {
            syslog(LOG_ERR, "Couldn't convert built-in DNS64 prefix");
            return false;
        }

        if (0 == memcmp(wellKnown.__in6_u.__u6_addr8, prefix.__in6_u.__u6_addr8, 16)) {
            isWellKnownB = true;
            syslog(LOG_DEBUG, "Parsing config: using the well-known prefix");
        }
    }

    return true;
}

void Configuration::resetConfiguration() {
    std::string currentConfigFile(configFile);
    *this = {};
    setConfigFile(currentConfigFile);
}