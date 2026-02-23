#pragma once

#include <arpa/nameser.h>
#include <unordered_set>
#include <spdlog/common.h>
#include <tins/dns.h>

// Defaults
extern spdlog::level::level_enum syslog_level;
extern bool use_syslog;

// Query type filtering
extern std::unordered_set<Tins::DNS::QueryType> enabled_qtypes;
bool qtype_enabled(const Tins::DNS::QueryType qtype);
void enable_qtype(const Tins::DNS::QueryType qtype);
void disable_qtype(const Tins::DNS::QueryType qtype);

extern std::unordered_set<ns_rcode> enabled_rcodes;
bool rcode_enabled(const ns_rcode rcode);
void enable_rcode(const ns_rcode rcode);
void disable_rcode(const ns_rcode rcode);
