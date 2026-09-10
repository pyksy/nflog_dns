/*
 * Copyright Antti Kultanen <antti.kultanen@molukki.com>
 *
 * nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file
 */

#pragma once

#include <arpa/nameser.h>
#include <unordered_set>
#include <unordered_map>
#include <spdlog/common.h>
#include <tins/dns.h>

const std::unordered_map<Tins::DNS::QueryType, std::string> dns_qtypes = {
    {Tins::DNS::A,           "A"},
    {Tins::DNS::NS,          "NS"},
    {Tins::DNS::MD,          "MD"},
    {Tins::DNS::MF,          "MF"},
    {Tins::DNS::CNAME,       "CNAME"},
    {Tins::DNS::SOA,         "SOA"},
    {Tins::DNS::MB,          "MB"},
    {Tins::DNS::MG,          "MG"},
    {Tins::DNS::MR,          "MR"},
    {Tins::DNS::NULL_R,      "NULL"},
    {Tins::DNS::WKS,         "WKS"},
    {Tins::DNS::PTR,         "PTR"},
    {Tins::DNS::HINFO,       "HINFO"},
    {Tins::DNS::MINFO,       "MINFO"},
    {Tins::DNS::MX,          "MX"},
    {Tins::DNS::TXT,         "TXT"},
    {Tins::DNS::RP,          "RP"},
    {Tins::DNS::AFSDB,       "AFSDB"},
    {Tins::DNS::X25,         "X25"},
    {Tins::DNS::ISDN,        "ISDN"},
    {Tins::DNS::RT,          "RT"},
    {Tins::DNS::NSAP,        "NSAP"},
    {Tins::DNS::NSAP_PTR,    "NSAP-PTR"},
    {Tins::DNS::SIG,         "SIG"},
    {Tins::DNS::KEY,         "KEY"},
    {Tins::DNS::PX,          "PX"},
    {Tins::DNS::GPOS,        "GPOS"},
    {Tins::DNS::AAAA,        "AAAA"},
    {Tins::DNS::LOC,         "LOC"},
    {Tins::DNS::NXT,         "NXT"},
    {Tins::DNS::EID,         "EID"},
    {Tins::DNS::NIMLOC,      "NIMLOC"},
    {Tins::DNS::SRV,         "SRV"},
    {Tins::DNS::ATMA,        "ATMA"},
    {Tins::DNS::NAPTR,       "NAPTR"},
    {Tins::DNS::KX,          "KX"},
    {Tins::DNS::CERTIFICATE, "CERT"},
    {Tins::DNS::A6,          "A6"},
    {Tins::DNS::DNAM,        "DNAME"},
    {Tins::DNS::SINK,        "SINK"},
    {Tins::DNS::OPT,         "OPT"},
    {Tins::DNS::APL,         "APL"},
    {Tins::DNS::DS,          "DS"},
    {Tins::DNS::SSHFP,       "SSHFP"},
    {Tins::DNS::IPSECKEY,    "IPSECKEY"},
    {Tins::DNS::RRSIG,       "RRSIG"},
    {Tins::DNS::NSEC,        "NSEC"},
    {Tins::DNS::DNSKEY,      "DNSKEY"},
    {Tins::DNS::DHCID,       "DHCID"},
    {Tins::DNS::NSEC3,       "NSEC3"},
    {Tins::DNS::NSEC3PARAM,  "NSEC3PARAM"},
};

static const std::unordered_map<ns_rcode, std::string> dns_rcodes = {
    {ns_r_noerror,  "NOERROR"},
    {ns_r_formerr,  "FORMERR"},
    {ns_r_servfail, "SERVFAIL"},
    {ns_r_nxdomain, "NXDOMAIN"},
    {ns_r_notimpl,  "NOTIMP"},
    {ns_r_refused,  "REFUSED"},
    {ns_r_yxdomain, "YXDOMAIN"},
    {ns_r_yxrrset,  "YXRRSET"},
    {ns_r_nxrrset,  "NXRRSET"},
    {ns_r_notauth,  "NOTAUTH"},
    {ns_r_notzone,  "NOTZONE"},
};

// Defaults
extern spdlog::level::level_enum syslog_level;
extern bool use_syslog;

extern bool use_default_qtypes;
extern bool use_default_rcodes;

// Query type filtering
extern std::unordered_set<Tins::DNS::QueryType> enabled_qtypes;
void enable_qtypes(const char* arg);
bool qtype_enabled(const Tins::DNS::QueryType qtype);
void clear_qtypes();

// Return code filtering
extern std::unordered_set<ns_rcode> enabled_rcodes;
void enable_rcodes(const char* arg);
bool rcode_enabled(const ns_rcode rcode);
void clear_rcodes();
