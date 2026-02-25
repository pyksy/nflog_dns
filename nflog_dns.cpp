/*
 * Written by Andreas Jaggi <andreas.jaggi@waterwave.ch> in December 2015
 * Written by Antti Kultanen <antti.kultanen@molukki.com> since August 2025
 *
 * nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file
 */

#include <resolv.h>
#define PROGRAM_NAME "nflog_dns"
#define DEFAULT_NFLOG_GROUP 123

#define	SYSLOG_NAMES

#define NFLOG_BUFFER_SIZE 65536

#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/syslog_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <tins/tins.h>
#include <iostream>
#include "config.h"
#include "version.h"

extern "C" {
	#include <libnetfilter_log/libnetfilter_log.h>
}

volatile sig_atomic_t exit_program_flag = 0;
volatile sig_atomic_t log_stats_flag = 0;

struct Stats {
    uint64_t invalid_packets = 0;
    uint64_t dns_responses = 0;
    uint64_t logged_records = 0;
    uint64_t logged_errors = 0;
} packet_stats;

std::string bool_to_string(const bool value) {
	return value ? "yes" : "no";
}

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

void print_help(char* prgname) {
	std::cout << "Usage: " << prgname << " [OPTION]..." << std::endl;
	std::cout << std::endl;
	std::cout << "Extract DNS replies from NFLOG group" << std::endl;
	std::cout << std::endl;
	std::cout << "  -g, --group=NUM          NFLOG group to bind (default: " << DEFAULT_NFLOG_GROUP << ")" << std::endl;
	std::cout << "  -s, --syslog             log replies to syslog instead of stdout" << std::endl;
	std::cout << "  -f, --facility=FACILITY  facility for syslog logging (default: user)" << std::endl;
	std::cout << "  -l, --level=LOGLEVEL     log level for syslog logging (default: info)" << std::endl;
	std::cout << "  -h, --help               print this help and exit" << std::endl;
	std::cout << "  -v, --version            show version and exit" << std::endl;
	std::cout << "      --log-a=BOOL         A record logging (default: " << bool_to_string(qtype_enabled(Tins::DNS::A)) << ")" << std::endl;
	std::cout << "      --log-aaaa=BOOL      AAAA record logging (default: " << bool_to_string(qtype_enabled(Tins::DNS::AAAA)) << ")" << std::endl;
	std::cout << "      --log-cname=BOOL     CNAME record logging (default: " << bool_to_string(qtype_enabled(Tins::DNS::CNAME)) << ")" << std::endl;
	std::cout << "      --log-mx=BOOL        MX record logging (default: " << bool_to_string(qtype_enabled(Tins::DNS::MX)) << ")" << std::endl;
	std::cout << "      --log-ptr=BOOL       PTR record logging (default: " << bool_to_string(qtype_enabled(Tins::DNS::PTR)) << ")" << std::endl;
	std::cout << "      --log-txt=BOOL       TXT record logging (default: " << bool_to_string(qtype_enabled(Tins::DNS::TXT)) << ")" << std::endl;
	std::cout << "      --log-noerror=BOOL   NOERROR replies logging (default: " << bool_to_string(rcode_enabled(ns_r_noerror)) << ")" << std::endl;
	std::cout << "      --log-formerr=BOOL   FORMERR error logging (default: " << bool_to_string(rcode_enabled(ns_r_formerr)) << ")" << std::endl;
	std::cout << "      --log-servfail=BOOL  SERVFAIL error logging (default: " << bool_to_string(rcode_enabled(ns_r_servfail)) << ")" << std::endl;
	std::cout << "      --log-nxdomain=BOOL  NXDOMAIN error logging (default: " << bool_to_string(rcode_enabled(ns_r_nxdomain)) << ")" << std::endl;
	std::cout << "      --log-notimpl=BOOL   NOTIMPL error logging (default: " << bool_to_string(rcode_enabled(ns_r_notimpl)) << ")" << std::endl;
	std::cout << "      --log-refused=BOOL   REFUSED error logging (default: " << bool_to_string(rcode_enabled(ns_r_refused)) << ")" << std::endl;
	std::cout << std::endl;
}

void log_stats() {
		static auto dns_logger = spdlog::get(PROGRAM_NAME);
		uint64_t packets_received = packet_stats.invalid_packets + packet_stats.dns_responses;
        dns_logger->log(syslog_level, "Statistics: received_packets={} invalid_packets={} dns_responses={} logged_errors={} logged_records={}",
            packets_received,
			packet_stats.invalid_packets, 
            packet_stats.dns_responses,
            packet_stats.logged_errors,
			packet_stats.logged_records);
}

void signal_handler(int signum) {
    if (signum == SIGUSR1) {
		log_stats_flag = 1;
	} else if (signum == SIGTERM || signum == SIGHUP || signum == SIGINT) {
        exit_program_flag = 1;
    }
}

bool is_number(const char* facility_arg) {
	// Check if number was given
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

static int callback(struct nflog_g_handle *gh __attribute__((unused)),
	struct nfgenmsg *nfmsg __attribute__((unused)),
	struct nflog_data *ldata,
	void *data __attribute__((unused)))
{
	uint8_t* payload;
	const int payload_len = nflog_get_payload(ldata, (char **)(&payload));
	if (!payload || payload_len < 1) {
		packet_stats.invalid_packets++;
		return 0;
	}
	const Tins::RawPDU rpdu = Tins::RawPDU(payload, payload_len);
	Tins::DNS dns;
	std::string source;

	// Minimum valid payload length (IP + UDP + DNS header)
	const size_t MIN_IPV4_DNS_LENGTH = 40;  // 20 + 8 + 12
	const size_t MIN_IPV6_DNS_LENGTH = 60;  // 40 + 8 + 12

	// Get IP version from payload and verify minimum length
	uint8_t ip_version = (payload[0] >> 4) & 0x0F;
	if ((ip_version == 4 && static_cast<size_t>(payload_len) < MIN_IPV4_DNS_LENGTH) ||
	    (ip_version == 6 && static_cast<size_t>(payload_len) < MIN_IPV6_DNS_LENGTH)) {
		packet_stats.invalid_packets++;
		return 0;
	}

	try {
		if (ip_version == 4) {
			Tins::IP ip = rpdu.to<Tins::IP>();
			dns = ip.rfind_pdu<Tins::RawPDU>().to<Tins::DNS>();
			source = ip.src_addr().to_string();
		} else if (ip_version == 6) {
			Tins::IPv6 ipv6 = rpdu.to<Tins::IPv6>();
			dns = ipv6.rfind_pdu<Tins::RawPDU>().to<Tins::DNS>();
			source = ipv6.src_addr().to_string();
		} else {
			// Unknown IP version, ignore
			packet_stats.invalid_packets++;
			return 0;
		}
	} catch (...) {
		// Malformed packet, ignore
		packet_stats.invalid_packets++;
		return 0;
	}

	try {
		if (dns.type() == Tins::DNS::RESPONSE) {
			packet_stats.dns_responses++;

			// Check return code
			const ns_rcode rcode = static_cast<ns_rcode>(dns.rcode());
			if (!rcode_enabled(rcode)) return 0; // rcode not enabled

			static auto dns_logger = spdlog::get(PROGRAM_NAME);
			if (rcode != ns_r_noerror) {
				std::string rcode_str = rcode_to_string(rcode);

				// Get query type from questions section
				std::string qtype_str;
				std::string qname;
				const auto& queries = dns.queries();
				if (!queries.empty()) {
					const Tins::DNS::QueryType qtype = queries[0].query_type();
					if (!qtype_enabled(qtype)) return 0;
					qtype_str = qtype_to_string(qtype);
					qname = queries[0].dname();
				} else {
					packet_stats.invalid_packets++;
					return 0;
				}

				dns_logger->log(syslog_level, "{} reply {} {} -> {}", 
					source, qtype_str, qname, rcode_str);
				packet_stats.logged_errors++;

			}

			// Check for answers
			for (const Tins::DNS::resource &answer : dns.answers()) {
				if (qtype_enabled(static_cast<Tins::DNS::QueryType>(answer.query_type()))) {
					const std::string qtype_str = qtype_to_string(static_cast<Tins::DNS::QueryType>(answer.query_type()));
					dns_logger->log(syslog_level, "{} reply {} {} -> {}", source, qtype_str, answer.dname(), answer.data());
					packet_stats.logged_records++;
				}
			}
		}

	} catch (...) {
		packet_stats.invalid_packets++;
		// Ignore exceptions
	}
	return 0;
}

int main(int argc, char *argv[]) 
{
	struct nflog_handle *h;
	struct nflog_g_handle *qh;
	ssize_t rv;
	static char buf[NFLOG_BUFFER_SIZE];
	uint16_t group = DEFAULT_NFLOG_GROUP;
	int syslog_facility = LOG_USER;
	int optindex = 0;
	int setting_value = -1;

	const option longopts[] = {
		{"log-a", required_argument, NULL, OPT_A},
		{"log-aaaa", required_argument, NULL, OPT_AAAA},
		{"log-cname", required_argument, NULL, OPT_CNAME},
		{"log-mx", required_argument, NULL, OPT_MX},
		{"log-ptr", required_argument, NULL, OPT_PTR},
		{"log-txt", required_argument, NULL, OPT_TXT},
		{"log-noerror", required_argument, NULL, OPT_NOERROR},
		{"log-formerr", required_argument, NULL, OPT_FORMERR},
		{"log-servfail", required_argument, NULL, OPT_SERVFAIL},
		{"log-nxdomain", required_argument, NULL, OPT_NXDOMAIN},
		{"log-notimpl", required_argument, NULL, OPT_NOTIMPL},
		{"log-refused", required_argument, NULL, OPT_REFUSED},
		{"facility", required_argument, NULL, 'f'},
		{"group", required_argument, NULL, 'g'},
		{"help", no_argument, NULL, 'h'},
		{"level", required_argument, NULL, 'l'},
		{"syslog", no_argument, NULL, 's'},
		{"version", no_argument, NULL, 'v'},
		{0, 0, 0, 0}
	};

	while (true) {
		const int opt = getopt_long(argc, argv, "f:g:hl:sv", longopts, &optindex);

		if (opt == -1) {
			break;
		}

		switch (opt) {
			case 'f':
				syslog_facility = parse_syslog_code(optarg, facilitynames);
				if (syslog_facility == -1) {
					std::cerr << "Error: Bad syslog facility name: " << optarg << std::endl;
					return 1;
				}
				break;

			case 'g':
				if (is_number(optarg)) {
					group = atoi(optarg);
				} else {
					std::cerr << "Error: Bad group number: " << optarg << std::endl;
					return 1;
				}
				break;

			case 'h':
				print_help(argv[0]);
				return 0;
				break;

			case 'l':
				syslog_level = spdlog::level::from_str(optarg);
				if (syslog_level == spdlog::level::off) {
					std::cerr << "Error: Bad syslog level: " << optarg << std::endl;
					return 1;
				}
				break;

			case 's':
				use_syslog = true;
				break;

			case 'v':
				std::cout << PROGRAM_NAME << " version " << PROGRAM_VERSION << std::endl;
				return 0;
				break;

			default:
				// Try logging options
				if (OPT_RECORDS_START < opt && opt < OPT_ERRORS_END) {
					setting_value = parse_bool(optarg);
					if (setting_value < 0) {
						std::cerr << "Error: Bad --" << longopts[optindex].name << " value: " << optarg << std::endl;
						return 1;
					}
					set_setting(static_cast<RecordOption>(opt), setting_value);
				} else {
					return 1;
				}
				break;
		}
	}

	// Setup nflog
	h = nflog_open();
	if (!h) {
		std::cerr << "Error: nflog_open() failed" << std::endl;
		return 1;
	}
	if (nflog_unbind_pf(h, AF_INET) < 0) {
		std::cerr << "Error: nflog_unbind_pf() failed" << std::endl;
		nflog_close(h);
		return 1;
	}
	if (nflog_bind_pf(h, AF_INET) < 0) {
		std::cerr << "Error: nflog_bind_pf() failed" << std::endl;
		nflog_close(h);
		return 1;
	}
	qh = nflog_bind_group(h, group);
	if (!qh) {
		std::cerr << "Error: nflog_bind_group() failed, no handle for group " << group << " -- is " << PROGRAM_NAME << " already running?" << std::endl;
		nflog_close(h);
		return 1;
	}
	if (nflog_set_nlbufsiz(qh, NFLOG_BUFFER_SIZE) < 0) {
		std::cerr << "Warning: nflog_set_nlbufsiz() failed, cannot set netlink buffer size" << std::endl;
	}
	if (nflog_set_mode(qh, NFULNL_COPY_PACKET, NFLOG_BUFFER_SIZE) < 0) {
		std::cerr << "Error: nflog_set_mode() failed, cannot set packet copy mode" << std::endl;
		nflog_unbind_group(qh);
		nflog_close(h);
		return 1;
	}

	// Setup logging
	std::shared_ptr<spdlog::sinks::sink> dns_logger_sink = nullptr;
	if (use_syslog) {
		dns_logger_sink = std::make_shared<spdlog::sinks::syslog_sink_mt>(PROGRAM_NAME, LOG_PID, syslog_facility, false);
	} else {
		dns_logger_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
	}
	auto dns_logger = std::make_shared<spdlog::logger>(PROGRAM_NAME, dns_logger_sink);
	spdlog::register_logger(dns_logger);
	dns_logger->set_level(syslog_level);
	dns_logger->log(syslog_level, "DNS logging initialized for NFLOG group {}", group);

	nflog_callback_register(qh, &callback, NULL);
	const int fd = nflog_fd(h);

	// Setup signal handlers
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sa.sa_flags = 0;  // Do NOT set SA_RESTART - we want EINTR
	sigemptyset(&sa.sa_mask);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	// Enter packet handling loop
	while (!exit_program_flag) {
		rv = recv(fd, buf, sizeof(buf), 0);

		if (log_stats_flag) {
			log_stats_flag = 0;
			log_stats();
		}

		if (rv > 0) {
			nflog_handle_packet(h, buf, rv);	
		}
		if (rv == 0) {
			std::cerr << "Error: recv() failed, nflog connection is closed" << std::endl;
			break;
		}
		if (rv < 0) {
			if (errno == EINTR) {
				// Signal interrupted, try again
				continue;
			} else {
				std::cerr << "Error: recv() failed with error " << strerror(errno) << std::endl;
				break;
			}
		}
	}

	dns_logger->log(syslog_level, "DNS logging stopped");
	log_stats();

	// Cleanup nflog
	nflog_unbind_group(qh);
	nflog_close(h);

	return 0;
}
