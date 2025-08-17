/*
 * Written by Andreas Jaggi <andreas.jaggi@waterwave.ch> in December 2015
 *
 * Updated by Antti Kultanen <pyksy at pyksy dot fi>
 */

#define PROGRAM_NAME "nflog_sniff"
#define PROGRAM_VERSION "0.0.0"
#define DEFAULT_NFLOG_GROUP 123

#define	SYSLOG_NAMES
#include <getopt.h>
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

bool is_number(const char& facility_arg) {
	// Check if number was given
	char* temp;
	unsigned long number = strtoul(optarg, &temp, 10);
	return optarg != temp && *temp == '\0' && number <= USHRT_MAX;
}

int parse_syslog_code(const char& facility_arg, const CODE* syslog_code_table) {
	if (is_number(*optarg)) {
		return atoi(optarg);
	}

	// Try matching string to given syslog code table
   for (int i=0; syslog_code_table[i].c_name != NULL; i++) {
        if (strcasecmp(&facility_arg, syslog_code_table[i].c_name) == 0) {
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
	try {
		dns = rpdu.to<IP>().rfind_pdu<RawPDU>().to<DNS>();
	} catch (malformed_packet&) {
		// Packet was not IPv4, try IPv6
		try {
			dns = rpdu.to<IPv6>().rfind_pdu<RawPDU>().to<DNS>();
		} catch (malformed_packet&) {
			// Packet was not IPv6 either, ignore it
			return true;
		}
	}

	try {
		if (dns.type() == DNS::RESPONSE) {
			auto dns_logger = spdlog::get(PROGRAM_NAME);

			for(const auto &answer : dns.answers()) {
				switch (answer.query_type()) {
					case DNS::A:
						dns_logger->log(syslog_level, "A {} -> {}", answer.dname(), answer.data());
						break;
					case DNS::AAAA:
						dns_logger->log(syslog_level, "AAAA {} -> {}", answer.dname(), answer.data());
						break;
					case DNS::CNAME:
						dns_logger->log(syslog_level, "CNAME {} -> {}", answer.dname(), answer.data());
						break;
					case DNS::PTR:
						dns_logger->log(syslog_level, "PTR {} -> {}", answer.dname(), answer.data());
						break;
					default:
						break;
				}
			}
		}
	} catch (...) {
			// Ignore exceptions
	}
	return true;
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
				syslog_facility = parse_syslog_code(*optarg, facilitynames);
				if (syslog_facility == -1) {
					std::cerr << "Error: Bad syslog facility name: " << optarg << std::endl;
					return 1;
				}
				break;

			case 'g':
				if (strcmp(optarg, "0") != 0) {
					if (is_number(*optarg)) {
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
				// std::cout << "testing: " << spdlog::level::from_str(optarg) << std::endl;
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

	h = nflog_open();
	if (!h) {
		fprintf(stderr, "error during nflog_open()\n");
		return 1;
	}
	if (nflog_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error nflog_unbind_pf()\n");
		return 1;
	}
	if (nflog_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nflog_bind_pf()\n");
		return 1;
	}
	qh = nflog_bind_group(h, group);
	if (!qh) {
		fprintf(stderr, "no handle for group %d\n", group);
		return 1;
	}

	if (nflog_set_mode(qh, NFULNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet copy mode\n");
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

	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		nflog_handle_packet(h, buf, rv);
	}
}
