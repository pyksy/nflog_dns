# Written by Andreas Jaggi <andreas.jaggi@waterwave.ch> in December 2015
# Written by Antti Kultanen <pyksy at pyksy dot fi>
#
# nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file

PREFIX ?= /usr/local
ETCDIR ?= /etc
SBINDIR ?= $(PREFIX)/sbin

all:
	g++ nflog_dns.cpp -std=c++11 -I/usr/include/libnetfilter_log -ltins -lnetfilter_log -lfmt -lspdlog -o nflog_dns

deb:
	dpkg-buildpackage -us -uc -b

rpm: nflog_dns.spec
	$(eval VERSION := $(shell grep '#define PROGRAM_VERSION' version.h | cut -d'"' -f2))
	mkdir -p ${HOME}/rpmbuild/SOURCES ${HOME}/rpmbuild/SPECS
	tar czf ${HOME}/rpmbuild/SOURCES/nflog-dns-$(VERSION).tar.gz \
		--exclude=.git --exclude=debian --exclude='*.deb' --exclude='*.rpm' \
		--transform 's,^\.,nflog-dns-$(VERSION),' .
	sed 's/^Version:.*/Version:        $(VERSION)/' nflog_dns.spec > ${HOME}/rpmbuild/SPECS/nflog_dns.spec
	rpmbuild -ba --define "_topdir ${HOME}/rpmbuild" ${HOME}/rpmbuild/SPECS/nflog_dns.spec

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
	install -s -Dm755 "nflog_dns" "$(DESTDIR)$(SBINDIR)/nflog_dns"

install-init:
	install -Dm755 "init.d/nflog_dns"  "$(DESTDIR)$(ETCDIR)/init.d/nflog_dns"
	sed -i 's#^DAEMON=.*#DAEMON="$(SBINDIR)/nflog_dns"#' "$(DESTDIR)$(ETCDIR)/init.d/nflog_dns"

install-systemd:
	install -Dm644 "systemd/nflog_dns.service" "$(DESTDIR)$(PREFIX)/lib/systemd/system/nflog_dns.service"

CONFIG_FILES := default/nflog_dns
install-config:
	$(foreach file, $(CONFIG_FILES), \
		test -e "$(DESTDIR)$(ETCDIR)/$(file)" || install -v -Dm644 "$(file)" "$(DESTDIR)$(ETCDIR)/$(file)";)

install: install-bin install-init install-systemd install-config

.PHONY: all clean distclean run-tests test install-bin install-init install-systemd install-config install deb rpm
