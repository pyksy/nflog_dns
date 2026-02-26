/*
 * Copyright Antti Kultanen <antti.kultanen@molukki.com>
 *
 * nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file
 */

#pragma once

#include <arpa/nameser.h>
#include <unordered_set>
#include <spdlog/common.h>
#include <tins/dns.h>

enum RecordOption {
	// Record logging options
	OPT_RECORDS_START = 1000,
	OPT_A,
	OPT_AAAA,
	OPT_CNAME,
	OPT_MX,
	OPT_PTR,
	OPT_TXT,
	OPT_RECORDS_END,
	// Error logging options
	OPT_ERRORS_START,
	OPT_NOERROR,
	OPT_FORMERR,
	OPT_SERVFAIL,
	OPT_NXDOMAIN,
	OPT_NOTIMPL,
	OPT_REFUSED,
	OPT_ERRORS_END
};

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
