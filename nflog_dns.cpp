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
	std::cout << "  -f, --facility=FACILITY  facility for syslog logging (default: user)" << std::endl;
	std::cout << "  -g, --group=NUM          NFLOG group to bind (default: " << DEFAULT_NFLOG_GROUP << ")" << std::endl;
	std::cout << "  -h, --help               print this help and exit" << std::endl;
	std::cout << "  -l, --loglevel=LOGLEVEL  log level for syslog logging (default: info)" << std::endl;
	std::cout << "  -q, --qtype=QTYPE,...    log QTYPE type DNS replies (default: A,AAAA)" << std::endl;
	std::cout << "  -r, --rcode=RCODE,...    log RCODE return code replies (default: NOERROR)" << std::endl;
	std::cout << "  -s, --syslog             log replies to syslog instead of stdout" << std::endl;
	std::cout << "  -u, --user=USER          user after dropping privileges (default: " << UNPRIVILEGED_USER << ")" << std::endl;
	std::cout << "  -v, --version            show version and exit" << std::endl;
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

	const option longopts[] = {
		{"facility", required_argument, NULL, 'f'},
		{"group", required_argument, NULL, 'g'},
		{"help", no_argument, NULL, 'h'},
		{"level", required_argument, NULL, 'l'},
		{"qtype", required_argument, NULL, 'q'},
		{"rcode", required_argument, NULL, 'r'},
		{"syslog", no_argument, NULL, 's'},
		{"user", required_argument, NULL, 'u'},
		{"version", no_argument, NULL, 'v'},
		{0, 0, 0, 0}
	};

	while (true) {
		const int opt = getopt_long(argc, argv, "f:g:hl:q:r:su:v", longopts, &optindex);

		if (opt == -1) {
			break;
		}

		switch (opt) {
			case 'f':
				syslog_facility = parse_syslog_code(optarg, facilitynames);
				if (syslog_facility == -1) {
					std::cerr << "Error: Bad syslog facility name: " << optarg << std::endl;
					return EXIT_FAILURE;
				}
				break;

			case 'g':
				if (is_number(optarg)) {
					group = atoi(optarg);
				} else {
					std::cerr << "Error: Bad group number: " << optarg << std::endl;
					return EXIT_FAILURE;
				}
				break;

			case 'h':
				print_help(argv[0]);
				return EXIT_SUCCESS;
				break;

			case 'l':
				syslog_level = spdlog::level::from_str(optarg);
				if (syslog_level == spdlog::level::off) {
					std::cerr << "Error: Bad syslog level: " << optarg << std::endl;
					return EXIT_FAILURE;
				}
				break;

			case 'q':
				if (use_default_qtypes) {
					clear_qtypes();
					use_default_qtypes = false;
				}
				try {
					enable_qtypes(optarg);
				} catch (const std::invalid_argument& e) {
					std::cerr << "Error: Invalid qtype: " << e.what() << std::endl;
					return EXIT_FAILURE;
				}
				break;

			case 'r':
				if (use_default_rcodes) {
					clear_rcodes();
					use_default_rcodes = false;
				}
				try {
					enable_rcodes(optarg);
				} catch (const std::invalid_argument& e) {
					std::cerr << "Error: Invalid rcode: " << e.what() << std::endl;
					return EXIT_FAILURE;
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
				return 1;
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
		std::cerr << "Error: nflog_unbind_pf() failed (" << strerror(errno) << ")" << std::endl;
		nflog_close(h);
		return 1;
	}
	// Note that AF_INET socket does receive both IPv4 and IPv6 packets.
	if (nflog_bind_pf(h, AF_INET) < 0) {
		std::cerr << "Error: nflog_bind_pf() failed (" << strerror(errno) << ")" << std::endl;
		nflog_close(h);
		return 1;
	}
	qh = nflog_bind_group(h, group);
	if (!qh) {
		std::cerr << "Error: nflog_bind_group() failed, no handle for group " << group << " (" << strerror(errno) << ") -- is " << PROGRAM_NAME << " already running?" << std::endl;
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
