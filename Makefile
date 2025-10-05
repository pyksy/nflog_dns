# Written by Andreas Jaggi <andreas.jaggi@waterwave.ch> in December 2015
# Written by Antti Kultanen <pyksy at pyksy dot fi>
#
# nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file

PREFIX := /usr/local
ETCDIR := /etc

all:
	g++ nflog_dns.cpp -std=c++11 -ltins -lnetfilter_log -lfmt -lspdlog -o nflog_dns

deb:
	dpkg-buildpackage -us -uc -b

clean-bin:
	rm -f nflog_dns

clean-deb:
	rm -rf debian/nflog-dns
	rm -rf debian/.debhelper
	rm -f debian/debhelper-build-stamp
	rm -f debian/*.debhelper.log
	rm -f debian/*.debhelper
	rm -f debian/files
	rm -f debian/*.substvars

clean: clean-bin clean-deb

distclean: clean

run-tests:
	bash ./test/run_tests.sh

test: run-tests

install-bin:
	install -s -Dm755 "nflog_dns" "$(DESTDIR)$(PREFIX)/sbin/nflog_dns"

install-init:
	install -Dm755 "init.d/nflog_dns"  "$(DESTDIR)$(ETCDIR)/init.d/nflog_dns"
	sed -i 's#^DAEMON=.*#DAEMON="$(PREFIX)/sbin/nflog_dns"#' "$(DESTDIR)$(ETCDIR)/init.d/nflog_dns"

install-systemd:
	install -Dm644 "systemd/nflog_dns.service" "$(DESTDIR)$(PREFIX)/lib/systemd/system/nflog_dns.service"

CONFIG_FILES := default/nflog_dns
install-config:
	$(foreach file, $(CONFIG_FILES), \
		test -e "$(DESTDIR)$(ETCDIR)/$(file)" || install -v -Dm644 "$(file)" "$(DESTDIR)$(ETCDIR)/$(file)";)

install: install-bin install-init install-systemd install-config

.PHONY: all clean distclean run-tests test install-bin install-init install-systemd install-config install deb
