# Written by Andreas Jaggi <andreas.jaggi@waterwave.ch> in December 2015
# Written by Antti Kultanen <pyksy at pyksy dot fi>
#
# nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file

PREFIX := /usr/local
ETCDIR := /etc

all:
	g++ nflog_dns.cpp -std=c++11 -ltins -lnetfilter_log -lfmt -lspdlog -o nflog_dns

clean:
	rm -f nflog_dns

distclean: clean

run-tests:
	bash ./test/run_tests.sh

test: run-tests

install-bin:
	install -s -Dm755 "nflog_dns" "$(PREFIX)/sbin/nflog_dns"

install-init:
	install -Dm755 "init.d/nflog_dns"  "$(ETCDIR)/init.d/nflog_dns"

CONFIG_FILES := default/nflog_dns
install-config:
	$(foreach file, $(CONFIG_FILES), \
		test -e "$(ETCDIR)/$(file)" || install -v -Dm644 "$(file)" "$(ETCDIR)/$(file)";)

install: install-bin install-init install-config
