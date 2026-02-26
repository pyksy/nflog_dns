/*
 * Copyright Antti Kultanen <antti.kultanen@molukki.com>
 *
 * nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file
 */

#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <spdlog/spdlog.h>
#include <tins/tins.h>
#include <tins/dns.h>
#include <arpa/nameser.h>
#define SYSLOG_NAMES
#include <syslog.h>
#include "utils.h"
#include "config.h"

Stats packet_stats;

std::string bool_to_string(const bool value) {
	return value ? "yes" : "no";
}

bool is_number(const char* facility_arg) {
	// Check if number was given
    if (!facility_arg || !isdigit((unsigned char)facility_arg[0])) return false;
	char* temp;
	unsigned long number = strtoul(facility_arg, &temp, 10);
	return facility_arg != temp && *temp == '\0' && number <= USHRT_MAX;
}

int parse_syslog_code(const char* facility_arg, const CODE* syslog_code_table) {
	if (is_number(facility_arg)) {
		return atoi(facility_arg);
	}

	// Try matching string to given syslog code table
   for (int i=0; syslog_code_table[i].c_name != NULL; i++) {
        if (strcasecmp(facility_arg, syslog_code_table[i].c_name) == 0) {
            return syslog_code_table[i].c_val;
        }
    }

	// No match, return error
	return -1;
}

int parse_bool(const char *str) {
	if (strcasecmp(str, "1") == 0 ||
		strcasecmp(str, "enable") == 0 ||
		strcasecmp(str, "on") == 0 ||
		strcasecmp(str, "true") == 0 ||
		strcasecmp(str, "yes") == 0)
		return 1;
	if (strcasecmp(str, "0") == 0 ||
		strcasecmp(str, "disable") == 0 ||
		strcasecmp(str, "off") == 0 ||
		strcasecmp(str, "false") == 0 ||
		strcasecmp(str, "no") == 0)
		return 0;

	// Cannot parse, return error
	return -1;
}

void set_setting(const RecordOption opt, const bool setting_value) {
	if (OPT_RECORDS_START < opt && opt < OPT_RECORDS_END) {
		Tins::DNS::QueryType qtype;
		switch (opt) {
			case OPT_A: qtype = Tins::DNS::A; break;
			case OPT_AAAA: qtype = Tins::DNS::AAAA; break;
			case OPT_CNAME: qtype = Tins::DNS::CNAME; break;
			case OPT_MX: qtype = Tins::DNS::MX; break;
			case OPT_PTR: qtype = Tins::DNS::PTR; break;
			case OPT_TXT: qtype = Tins::DNS::TXT; break;
			default: return;
		}
		if (setting_value)
			enable_qtype(qtype);
		else
			disable_qtype(qtype);
	} else if (OPT_ERRORS_START < opt && opt < OPT_ERRORS_END){
		ns_rcode rcode;
		switch (opt) {
		    case OPT_NOERROR: rcode = ns_r_noerror; break;
			case OPT_FORMERR: rcode = ns_r_formerr; break;
			case OPT_SERVFAIL: rcode = ns_r_servfail; break;
			case OPT_NXDOMAIN: rcode = ns_r_nxdomain; break;
			case OPT_NOTIMPL: rcode = ns_r_notimpl; break;
			case OPT_REFUSED: rcode = ns_r_refused; break;
			default: return;
		}
		if (setting_value)
			enable_rcode(rcode);
		else
			disable_rcode(rcode);
	}
}

 std::string qtype_to_string(const Tins::DNS::QueryType queryType) {
	switch (queryType) {
		case Tins::DNS::A: return "A"; break;
		case Tins::DNS::AAAA: return "AAAA"; break;
		case Tins::DNS::CNAME: return "CNAME"; break;
		case Tins::DNS::MX: return "MX"; break;
		case Tins::DNS::PTR: return "PTR"; break;
		case Tins::DNS::TXT: return "TXT"; break;
		default: return "(" + std::to_string(queryType) + ")"; break;
	}
}

std::string rcode_to_string(const ns_rcode rcode) {
	switch (rcode) {
		case ns_r_noerror: return "NOERROR"; break;
		case ns_r_formerr: return "FORMERR"; break;
		case ns_r_servfail: return "SERVFAIL"; break;
		case ns_r_nxdomain: return "NXDOMAIN"; break;
		case ns_r_notimpl: return "NOTIMPL"; break;
		case ns_r_refused: return "REFUSED"; break;
		default: return "(" + std::to_string(rcode) + ")"; break;
	}
}

void log_stats(spdlog::logger& dns_logger) {
    uint64_t packets_received = packet_stats.invalid_packets + packet_stats.dns_responses;
    dns_logger.log(dns_logger.level(), "Statistics: received_packets={} invalid_packets={} dns_responses={} logged_errors={} logged_records={}",
        packets_received,
        packet_stats.invalid_packets,
        packet_stats.dns_responses,
        packet_stats.logged_errors,
        packet_stats.logged_records);
}


void process_dns_packet(const uint8_t* payload,
                        const int payload_len,
                        spdlog::logger& dns_logger) {
    // Minimum valid payload length (IP + UDP + DNS header)
	const size_t MIN_IPV4_DNS_LENGTH = 40;  // 20 + 8 + 12
	const size_t MIN_IPV6_DNS_LENGTH = 60;  // 40 + 8 + 12

	// Get IP version from payload and verify minimum length
	const uint8_t ip_version = (payload[0] >> 4) & 0x0F;
	if ((ip_version == 4 && static_cast<size_t>(payload_len) < MIN_IPV4_DNS_LENGTH) ||
	    (ip_version == 6 && static_cast<size_t>(payload_len) < MIN_IPV6_DNS_LENGTH)) {
		packet_stats.invalid_packets++;
		return;
	}

    Tins::DNS dns;
    std::string source;
    try {
        const Tins::RawPDU rpdu(payload, payload_len);
		if (ip_version == 4) {
			const Tins::IP ip = rpdu.to<Tins::IP>();
			dns = ip.rfind_pdu<Tins::RawPDU>().to<Tins::DNS>();
			source = ip.src_addr().to_string();
		} else if (ip_version == 6) {
			const Tins::IPv6 ipv6 = rpdu.to<Tins::IPv6>();
			dns = ipv6.rfind_pdu<Tins::RawPDU>().to<Tins::DNS>();
			source = ipv6.src_addr().to_string();
		} else {
			// Unknown IP version, ignore
			packet_stats.invalid_packets++;
			return;
		}
	} catch (...) {
		// Malformed packet, ignore
		packet_stats.invalid_packets++;
		return;
	}

	try {
		if (dns.type() == Tins::DNS::RESPONSE) {
			packet_stats.dns_responses++;

			// Check return code
			const ns_rcode rcode = static_cast<ns_rcode>(dns.rcode());
			if (!rcode_enabled(rcode)) return; // rcode not enabled

			if (rcode != ns_r_noerror) {
				std::string rcode_str = rcode_to_string(rcode);

				// Get query type from questions section
				std::string qtype_str;
				std::string qname;
				const auto& queries = dns.queries();
				if (!queries.empty()) {
					const Tins::DNS::QueryType qtype = queries[0].query_type();
					if (!qtype_enabled(qtype)) return;
					qtype_str = qtype_to_string(qtype);
					qname = queries[0].dname();
				} else {
					packet_stats.invalid_packets++;
					return;
				}

				dns_logger.log(dns_logger.level(), "{} reply {} {} -> {}",
					source, qtype_str, qname, rcode_str);
				packet_stats.logged_errors++;
			}

			// Check for answers
			for (const Tins::DNS::resource &answer : dns.answers()) {
                const Tins::DNS::QueryType qtype = static_cast<Tins::DNS::QueryType>(answer.query_type());
				if (qtype_enabled(qtype)) {
					const std::string qtype_str = qtype_to_string(qtype);
					dns_logger.log(dns_logger.level(), "{} reply {} {} -> {}", source, qtype_str, answer.dname(), answer.data());
					packet_stats.logged_records++;
				}
			}
		}

	} catch (...) {
		packet_stats.invalid_packets++;
		// Ignore exceptions
	}
}
