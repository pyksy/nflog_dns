/*
 * Copyright Antti Kultanen <antti.kultanen@molukki.com>
 *
 * nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file
 */

#include "config.h"

// Defaults
spdlog::level::level_enum syslog_level = spdlog::level::info;
bool use_syslog = false;

bool use_default_qtypes = true;
bool use_default_rcodes = true;

// qtypes; Initialize with A and AAAA qtypes enabled by default
std::unordered_set<Tins::DNS::QueryType> enabled_qtypes = {
    Tins::DNS::A,
    Tins::DNS::AAAA
};
void enable_qtypes(const char* arg)
{
    std::string input(arg);
    std::size_t start = 0;

    while (start < input.size()) {
        std::size_t comma = input.find(',', start);
        std::string qtype = input.substr(
            start,
            comma == std::string::npos ? std::string::npos : comma - start
        );

        // Convert to uppercase.
        for (std::size_t i = 0; i < qtype.size(); ++i) {
            qtype[i] = static_cast<char>(
                std::toupper(static_cast<unsigned char>(qtype[i]))
            );
        }

        // Skip empty
        if (qtype.empty()) {
            continue;
        }

        bool found = false;
        for (std::unordered_map<Tins::DNS::QueryType, std::string>::const_iterator it =
                 dns_qtypes.begin();
             it != dns_qtypes.end();
             ++it) {
            if (it->second == qtype) {
                enabled_qtypes.insert(it->first);
                found = true;
                break;
            }
        }

        if (!found) {
            throw std::invalid_argument("unknown DNS qtype: " + qtype);
        }

        if (comma == std::string::npos)
            break;

        start = comma + 1;
    }
}
bool qtype_enabled(const Tins::DNS::QueryType qtype) {
    return enabled_qtypes.find(qtype) != enabled_qtypes.end();
}
void clear_qtypes() {
    enabled_qtypes.clear();
}

// rcodes; Initialize with NOERROR rcode enabled by default
std::unordered_set<ns_rcode> enabled_rcodes = {
    ns_r_noerror
};
void enable_rcodes(const char* arg)
{
    std::string input(arg);
    std::size_t start = 0;

    while (start < input.size()) {
        std::size_t comma = input.find(',', start);

        std::string name = input.substr(
            start,
            comma == std::string::npos
                ? std::string::npos
                : comma - start
        );

        // Convert to uppercase.
        for (std::size_t i = 0; i < name.size(); ++i) {
            name[i] = static_cast<char>(
                std::toupper(static_cast<unsigned char>(name[i]))
            );
        }

        if (name.empty()) {
            continue;
        }

        bool found = false;

        for (std::unordered_map<ns_rcode, std::string>::const_iterator it =
                 dns_rcodes.begin();
             it != dns_rcodes.end();
             ++it) {
            if (it->second == name) {
                enabled_rcodes.insert(it->first);
                found = true;
                break;
            }
        }

        if (!found) {
            throw std::invalid_argument("unknown DNS rcode: " + name);
        }

        if (comma == std::string::npos)
            break;

        start = comma + 1;
    }
}
bool rcode_enabled(const ns_rcode rcode) {
    return enabled_rcodes.find(rcode) != enabled_rcodes.end();
}
void clear_rcodes() {
    enabled_rcodes.clear();
}
