/*
 * Written by Andreas Jaggi <andreas.jaggi@waterwave.ch> in December 2015
 * Written by Antti Kultanen <antti.kultanen@molukki.com> since August 2025
 *
 * nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file
 */

#define PROGRAM_NAME "nflog_dns"
#define DEFAULT_NFLOG_GROUP 123
#define UNPRIVILEGED_USER "nobody"
#define NFLOG_BUFFER_SIZE 65536

#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <unistd.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/syslog_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <tins/tins.h>
#include <iostream>
#include "config.h"
#include "utils.h"
#include "version.h"

extern "C" {
	#include <libnetfilter_log/libnetfilter_log.h>
}

volatile sig_atomic_t exit_program_flag = 0;
volatile sig_atomic_t log_stats_flag = 0;
const char* unprivileged_user = UNPRIVILEGED_USER;

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
	std::cout << "  -u, --user=USER          user after dropping privileges (default: " << UNPRIVILEGED_USER << ")" << std::endl;
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

void signal_handler(int signum) {
    if (signum == SIGUSR1) {
		log_stats_flag = 1;
	} else if (signum == SIGTERM || signum == SIGHUP || signum == SIGINT) {
        exit_program_flag = 1;
    }
}

static int callback(struct nflog_g_handle *gh __attribute__((unused)),
	struct nfgenmsg *nfmsg __attribute__((unused)),
	struct nflog_data *ldata,
	void *data)
{
	uint8_t* payload;
	const int payload_len = nflog_get_payload(ldata, (char **)(&payload));
	if (!payload || payload_len < 1) {
		packet_stats.invalid_packets++;
		return 0;
	}
	spdlog::logger* dns_logger = static_cast<spdlog::logger*>(data);
	process_dns_packet(payload, payload_len, *dns_logger);

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
		{"user", required_argument, NULL, 'u'},
		{"version", no_argument, NULL, 'v'},
		{0, 0, 0, 0}
	};

	while (true) {
		const int opt = getopt_long(argc, argv, "f:g:hl:su:v", longopts, &optindex);

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

			case 'u':
				unprivileged_user = optarg;
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
	// Note that AF_INET socket does receive both IPv4 and IPv6 packets.
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

	nflog_callback_register(qh, &callback, static_cast<void*>(dns_logger.get()));

	// Root no longer needed after setup, drop privileges
    if (geteuid() == 0) {
		const struct passwd* pw = getpwnam(unprivileged_user);
		if (!pw) {
			std::cerr << "Error: Cannot find user " << unprivileged_user << std::endl;
			nflog_unbind_group(qh);
			nflog_close(h);
			return 1;
		}

		if (initgroups(pw->pw_name, pw->pw_gid) < 0 ||
			setgid(pw->pw_gid) < 0 ||
			setuid(pw->pw_uid) < 0) {
			std::cerr << "Error: Cannot drop to user " << unprivileged_user << ": " << strerror(errno) << std::endl;
			nflog_unbind_group(qh);
			nflog_close(h);
			return 1;
		}
	}

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
		const int errno_recv = errno;

		if (log_stats_flag) {
			log_stats_flag = 0;
			log_stats(*dns_logger);
		}

		if (rv > 0) {
			nflog_handle_packet(h, buf, rv);	
		}
		if (rv == 0) {
			std::cerr << "Error: recv() failed, nflog connection is closed" << std::endl;
			break;
		}
		if (rv < 0) {
			if (errno_recv == EINTR) {
				// Signal interrupted, try again
				continue;
			} else {
				std::cerr << "Error: recv() failed with error " << strerror(errno) << std::endl;
				break;
			}
		}
	}

	dns_logger->log(syslog_level, "DNS logging stopped");
	log_stats(*dns_logger);

	// Cleanup nflog
	nflog_unbind_group(qh);
	nflog_close(h);

	return 0;
}
