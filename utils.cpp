/*
 * Copyright Antti Kultanen <antti.kultanen@molukki.com>
 *
 * nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file
 */

#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <spdlog/spdlog.h>
#include <tins/tins.h>
#include <tins/dns.h>
#include <arpa/nameser.h>
#define SYSLOG_NAMES
#include <syslog.h>
#include "utils.h"
#include "config.h"


static bool is_printable(const std::string& data) {
	for (unsigned char c : data) {
		if (c < 0x20 || c > 0x7e) {
			return false;
		}
	}
	return true;
}

static std::string hex_encode(const std::string& data) {
	static const char hex_digits[] = "0123456789abcdef";
	std::string out;
	out.reserve(data.size() * 2);
	for (unsigned char c : data) {
		out.push_back(hex_digits[c >> 4]);
		out.push_back(hex_digits[c & 0x0f]);
	}
	return out;
}

// Decode TXT RDATA because Tins::DNS::resource::data() returns TXT RDATA
// with the length-prefix byte(s) still attached. Returns false if the 
// RDATA is a malformed.
static bool decode_txt(const std::string& data, std::string& out) {
	std::size_t pos = 0;
	while (pos < data.size()) {
		const std::size_t len = static_cast<unsigned char>(data[pos]);
		++pos;
		if (pos + len > data.size()) {
			return false;
		}
		if (!out.empty()) {
			out += " ";
		}
		out += data.substr(pos, len);
		pos += len;
	}
	return true;
}

// Render RDATA for logging. TXT gets its character-string length
// prefixes stripped, everything else is passed thru if already
// printable ASCII, otherwise hex-encoded
static std::string format_rdata(const Tins::DNS::QueryType qtype, const std::string& data, bool& raw) {
	if (qtype == Tins::DNS::TXT) {
		std::string decoded;
		if (decode_txt(data, decoded) && is_printable(decoded)) {
			raw = false;
			return decoded;
		}
	}
	if (is_printable(data)) {
		raw = false;
		return data;
	}
	raw = true;
	return "0x" + hex_encode(data);
}

// Escape a string for safe embedding in a JSON string literal.
static std::string json_escape(const std::string& data) {
	std::string out;
	out.reserve(data.size());
	for (unsigned char c : data) {
		switch (c) {
			case '"':  out += "\\\""; break;
			case '\\': out += "\\\\"; break;
			default:
				if (c < 0x20 || c > 0x7e) {
					char buf[7];
					std::snprintf(buf, sizeof(buf), "\\u%04x", c);
					out += buf;
				} else {
					out += static_cast<char>(c);
				}
		}
	}
	return out;
}

// ISO 8601 / RFC 3339 UTC timestamp with millisecond precision
static std::string current_timestamp() {
	const auto now = std::chrono::system_clock::now();
	const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
		now.time_since_epoch()) % 1000;
	const std::time_t t = std::chrono::system_clock::to_time_t(now);
	struct tm tm_buf;
	gmtime_r(&t, &tm_buf);
	char datetime[32];
	std::strftime(datetime, sizeof(datetime), "%Y-%m-%dT%H:%M:%S", &tm_buf);
	char out[40];
	std::snprintf(out, sizeof(out), "%s.%03dZ", datetime, static_cast<int>(ms.count()));
	return std::string(out);
}

std::string json_message(const std::string& type, const std::string& message) {
	return "{\"timestamp\":\"" + current_timestamp() + "\","
	       "\"type\":\"" + json_escape(type) + "\","
	       "\"message\":\"" + json_escape(message) + "\"}";
}

// JSON entry for an rcode-error reply;
// no resource record to report, so no "data" nor "raw" fields
static std::string json_error_line(const std::uint16_t id,
                                    const std::string& source,
                                    const std::string& qtype,
                                    const std::string& name,
                                    const std::string& rcode) {
	return "{\"timestamp\":\"" + current_timestamp() + "\","
	       "\"type\":\"reply\","
	       "\"id\":" + std::to_string(id) + ","
	       "\"source\":\"" + json_escape(source) + "\","
	       "\"qtype\":\"" + json_escape(qtype) + "\","
	       "\"name\":\"" + json_escape(name) + "\","
	       "\"rcode\":\"" + json_escape(rcode) + "\"}";
}

// JSON entry for a resource record, with data and
// raw fields; raw is true when data is hex fallback
static std::string json_record_line(const std::uint16_t id,
                                     const std::string& source,
                                     const std::string& qtype,
                                     const std::string& name,
                                     const std::string& rcode,
                                     const std::string& data,
                                     const bool raw) {
	std::string out = "{\"timestamp\":\"" + current_timestamp() + "\","
	                   "\"type\":\"reply\","
	                   "\"id\":" + std::to_string(id) + ","
	                   "\"source\":\"" + json_escape(source) + "\","
	                   "\"qtype\":\"" + json_escape(qtype) + "\","
	                   "\"name\":\"" + json_escape(name) + "\","
	                   "\"rcode\":\"" + json_escape(rcode) + "\","
	                   "\"data\":\"" + json_escape(data) + "\"";
	if (raw) {
		out += ",\"raw\":true";
	}
	out += "}";
	return out;
}

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

std::string qtype_to_string(Tins::DNS::QueryType qtype)
{
    std::unordered_map<Tins::DNS::QueryType, std::string>::const_iterator it =
        dns_qtypes.find(qtype);

    if (it != dns_qtypes.end())
        return it->second;

    return "UNKNOWN";
}

std::string rcode_to_string(ns_rcode rcode)
{
    std::unordered_map<ns_rcode, std::string>::const_iterator it =
        dns_rcodes.find(rcode);

    if (it != dns_rcodes.end())
        return it->second;

    return "UNKNOWN";
}

void log_stats(spdlog::logger& dns_logger) {
    uint64_t packets_received = packet_stats.invalid_packets + packet_stats.dns_responses;
    if (use_json) {
        dns_logger.log(dns_logger.level(),
            "{{\"timestamp\":\"{}\",\"type\":\"stats\",\"received_packets\":{},\"invalid_packets\":{},"
            "\"dns_responses\":{},\"logged_errors\":{},\"logged_records\":{}}}",
            current_timestamp(),
            packets_received,
            packet_stats.invalid_packets,
            packet_stats.dns_responses,
            packet_stats.logged_errors,
            packet_stats.logged_records);
        return;
    }
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

				if (use_json) {
					dns_logger.log(dns_logger.level(), "{}",
						json_error_line(dns.id(), source, qtype_str, qname, rcode_str));
				} else {
					dns_logger.log(dns_logger.level(), "{} reply {} {} -> {} (id={})",
						source, qtype_str, qname, rcode_str, dns.id());
				}
				packet_stats.logged_errors++;
			}

			// Check for answers
			for (const Tins::DNS::resource &answer : dns.answers()) {
                const Tins::DNS::QueryType qtype = static_cast<Tins::DNS::QueryType>(answer.query_type());
				if (qtype_enabled(qtype)) {
					const std::string qtype_str = qtype_to_string(qtype);
					bool raw = false;
					const std::string data = format_rdata(qtype, answer.data(), raw);
					if (use_json) {
						dns_logger.log(dns_logger.level(), "{}",
							json_record_line(dns.id(), source, qtype_str, answer.dname(),
							                  rcode_to_string(rcode), data, raw));
					} else {
						dns_logger.log(dns_logger.level(), "{} reply {} {} -> {} (id={})",
							source, qtype_str, answer.dname(), data, dns.id());
					}
					packet_stats.logged_records++;
				}
			}
		}

	} catch (...) {
		packet_stats.invalid_packets++;
		// Ignore exceptions
	}
}
