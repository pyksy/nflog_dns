/*
 * Written by Andreas Jaggi <andreas.jaggi@waterwave.ch> in December 2015
 *
 * Updated by Antti Kultanen <pyksy at pyksy dot fi>
 */

#define DEFAULT_NFLOG_GROUP 123

#include <getopt.h>
#include <tins/tins.h>
#include <iostream>

extern "C"{
#include <libnetfilter_log/libnetfilter_log.h>
}

using namespace Tins;

static int callback(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *ldata, void *data)
{
	uint32_t payload_len;
	uint8_t* payload;
	payload_len = nflog_get_payload(ldata, (char **)(&payload));
	RawPDU rpdu = RawPDU(payload, payload_len);
	try {
		DNS dns = rpdu.to<IP>().rfind_pdu<UDP>().rfind_pdu<RawPDU>().to<DNS>();
	
		if ( dns.type() == DNS::RESPONSE ) {
			for(const auto &answer : dns.answers()) {
				if ( answer.type() == DNS::A )
					std::cout << "answer(A)[" << answer.ttl() << "]: " << answer.dname() << " -> " << answer.data() << std::endl;
				if ( answer.type() == DNS::AAAA )
					std::cout << "answer(AAAA)[" << answer.ttl() << "]: " << answer.dname() << " -> " << answer.data() << std::endl;
				if ( answer.type() == DNS::CNAME )
					std::cout << "answer(CNAME)[" << answer.ttl() << "]: " << answer.dname() << " -> " << answer.data() << std::endl;
			}
		}
	} catch (malformed_packet&) {
		/* ignore malformed packets */
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

	option longopts[] = {
		{"group", required_argument, NULL, 'g'},
		{"help", no_argument, NULL, 'h'},
		{0}
	};

		while (true) {
		const int opt = getopt_long(argc, argv, "g:h", longopts, 0);

		if (opt == -1) {
			break;
		}

		switch (opt) {
			case 'g':
				group = atoi(optarg);
				break;

			case 'h':
				std::cout << "Print help" << std::endl;
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

	nflog_callback_register(qh, &callback, NULL);

	int fd = nflog_fd(h);

	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		nflog_handle_packet(h, buf, rv);
	}
}
