/*
 * Written by Andreas Jaggi <andreas.jaggi@waterwave.ch> in December 2015
 * Written by Antti Kultanen <pyksy at pyksy dot fi>
 *
 * nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file
 */

#define PROGRAM_NAME "nflog_dns"
#define PROGRAM_VERSION "0.0.0"
#define DEFAULT_NFLOG_GROUP 123

#define	SYSLOG_NAMES
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/syslog_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <tins/tins.h>
#include <iostream>

extern "C"{
#include <libnetfilter_log/libnetfilter_log.h>
}

using namespace Tins;

bool use_syslog = false;
spdlog::level::level_enum syslog_level = spdlog::level::info;

void print_help(char* prgname) {
	std::cout << "Usage: " << prgname << " [OPTION]..." << std::endl;
	std::cout << "" << std::endl;
	std::cout << "Extract DNS replies from NFLOG group" << std::endl;
	std::cout << "" << std::endl;
	std::cout << "  -g, --group       NFLOG group to bind (default: " << DEFAULT_NFLOG_GROUP << ")" << std::endl;
	std::cout << "  -s, --syslog      log replies to syslog instead of stdout" << std::endl;
	std::cout << "  -f, --facility    facility for syslog logging (default: user)" << std::endl;
	std::cout << "  -l, --level       log level for syslog logging (default: info)" << std::endl;
    std::cout << "  -h, --help        print this help and exit" << std::endl;
    std::cout << "  -v, --version     show version and exit" << std::endl;
	std::cout << "" << std::endl;
	std::cout << "" << std::endl;
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

static int callback(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *ldata, void *data)
{
	uint32_t payload_len;
	uint8_t* payload;
	payload_len = nflog_get_payload(ldata, (char **)(&payload));
	RawPDU rpdu = RawPDU(payload, payload_len);
	DNS dns;
	IP ip;
	IPv6 ipv6;
	std::string source;

	try {
		ip = rpdu.to<IP>();
		dns = ip.rfind_pdu<RawPDU>().to<DNS>();
		source = ip.src_addr().to_string();
	} catch (malformed_packet&) {
		// Packet was not IPv4, try IPv6
		try {
			ipv6 = rpdu.to<IPv6>();
			dns = ipv6.rfind_pdu<RawPDU>().to<DNS>();
			source = ipv6.src_addr().to_string();
		} catch (malformed_packet&) {
			// Packet was not IPv6 either, ignore it
			return 0;
		}
	}

	try {
		if (dns.type() == DNS::RESPONSE) {
			auto dns_logger = spdlog::get(PROGRAM_NAME);
			if (!dns_logger) return 0;

			for(const auto &answer : dns.answers()) {
				switch (answer.query_type()) {
					case DNS::A:
						dns_logger->log(syslog_level, "{} reply A {} -> {}", source, answer.dname(), answer.data());
						break;
					case DNS::AAAA:
						dns_logger->log(syslog_level, "{} reply AAAA {} -> {}", source, answer.dname(), answer.data());
						break;
					case DNS::CNAME:
						dns_logger->log(syslog_level, "{} reply CNAME {} -> {}", source, answer.dname(), answer.data());
						break;
					case DNS::PTR:
						dns_logger->log(syslog_level, "{} reply PTR {} -> {}", source, answer.dname(), answer.data());
						break;
					default:
						break;
				}
			}
		}
	} catch (...) {
		// Ignore exceptions
	}
	return 0;
}

int main(int argc, char *argv[]) 
{
	struct nflog_handle *h;
	struct nflog_g_handle *qh;
	ssize_t rv;
	char buf[4096];
	uint16_t group = DEFAULT_NFLOG_GROUP;
	int syslog_facility = LOG_USER;

	option longopts[] = {
		{"facility", required_argument, NULL, 'f'},
		{"group", required_argument, NULL, 'g'},
		{"help", no_argument, NULL, 'h'},
		{"level", required_argument, NULL, 'l'},
		{"syslog", no_argument, NULL, 's'},
		{"version", no_argument, NULL, 'v'},
		{0}
	};

		while (true) {
		const int opt = getopt_long(argc, argv, "f:g:hl:sv", longopts, 0);

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
				if (strcmp(optarg, "0") != 0) {
					if (is_number(optarg)) {
						group = atoi(optarg);
					} else {
						std::cerr << "Error: Bad group number: " << optarg << std::endl;
						return 1;
					}
				} else {
					group = 0;
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
				return 1;
		}
	}

	// Setup nflog
	h = nflog_open();
	if (!h) {
		std::cerr << "error during nflog_open()" << std::endl;
		return 1;
	}
	if (nflog_unbind_pf(h, AF_INET) < 0) {
		std::cerr << "error nflog_unbind_pf()" << std::endl;
		return 1;
	}
	if (nflog_bind_pf(h, AF_INET) < 0) {
		std::cerr << "error during nflog_bind_pf()" << std::endl;
		return 1;
	}
	qh = nflog_bind_group(h, group);
	if (!qh) {
		std::cerr << "no handle for group " << group << " -- is " << PROGRAM_NAME << " already running?" << std::endl;
		return 1;
	}

	if (nflog_set_mode(qh, NFULNL_COPY_PACKET, 0xffff) < 0) {
		std::cerr << "can't set packet copy mode" << std::endl;
		return 1;
	}

	// Setup logging
	std::shared_ptr<spdlog::sinks::sink> dns_logger_sink = NULL;
	if (use_syslog) {
		dns_logger_sink = std::make_shared<spdlog::sinks::syslog_sink_mt>(PROGRAM_NAME, LOG_PID, syslog_facility, false);
	} else {
		dns_logger_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
	}
	auto dns_logger = std::make_shared<spdlog::logger>(PROGRAM_NAME, dns_logger_sink);
	spdlog::register_logger(dns_logger);
	dns_logger->log(syslog_level, "DNS logging initialized for NFLOG group {}", group);

	nflog_callback_register(qh, &callback, NULL);
	int fd = nflog_fd(h);

	// Enter packet handling loop
	while (1) {
		rv = recv(fd, buf, sizeof(buf), 0);

		if (rv > 0) {
			nflog_handle_packet(h, buf, rv);	
		}
		if (rv == 0) {
			std::cerr << "nflog connection closed" << std::endl;
			break;
		}
		if (rv < 0) {
			if (errno == EINTR) {
				// Signal interrupted, try again
				continue;
			} else {
				std::cerr << "recv error " << strerror(errno) << std::endl;
				break;
			}
		}
	}

	// Cleanup nflog
	nflog_unbind_group(qh);
	nflog_close(h);
}
