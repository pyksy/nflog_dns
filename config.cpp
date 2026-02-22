#include "config.h"

// Defaults
spdlog::level::level_enum syslog_level = spdlog::level::info;
bool use_syslog = false;

// Initialize with all configurable qtypes enabled by default
std::unordered_set<Tins::DNS::QueryType> enabled_qtypes = {
    Tins::DNS::A,
    Tins::DNS::AAAA,
    Tins::DNS::CNAME,
    Tins::DNS::MX,
    Tins::DNS::PTR,
    Tins::DNS::TXT
};
bool qtype_enabled(Tins::DNS::QueryType qtype) {
    return enabled_qtypes.find(qtype) != enabled_qtypes.end();
}
void enable_qtype(Tins::DNS::QueryType qtype) {
    enabled_qtypes.insert(qtype);
}
void disable_qtype(Tins::DNS::QueryType qtype) {
    enabled_qtypes.erase(qtype);
}

// Initialize with only successful rcode by default
std::unordered_set<ns_rcode> enabled_rcodes = {
    ns_r_noerror
    // ns_r_formerr
    // ns_r_servfail
    // ns_r_nxdomain
    // ns_r_notimpl
    // ns_r_refused
};
bool rcode_enabled(ns_rcode rcode) {
    return enabled_rcodes.find(rcode) != enabled_rcodes.end();
}
void enable_rcode(ns_rcode rcode) {
    enabled_rcodes.insert(rcode);
}
void disable_rcode(ns_rcode rcode) {
    enabled_rcodes.erase(rcode);
}
