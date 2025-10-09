# Written by Andreas Jaggi <andreas.jaggi@waterwave.ch> in December 2015
# Written by Antti Kultanen <antti.kultanen@molukki.com> since August 2025
#
# nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file

PREFIX ?= /usr/local
ETCDIR ?= /etc
SBINDIR ?= $(PREFIX)/sbin
CXX ?= c++
CXXFLAGS ?= -std=c++11 -Wall -Wextra -Werror -pedantic
CXXEXTRAFLAGS ?= 
INSTALL_SYSVINIT ?= 1
INSTALL_SYSTEMD ?= 1

all:
	$(CXX) $(CXXFLAGS) $(CXXEXTRAFLAGS) nflog_dns.cpp -I/usr/include/libnetfilter_log -ltins -lnetfilter_log -lfmt -lspdlog -o nflog_dns

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

debug: CXXEXTRAFLAGS = -fsanitize=address
debug: all

clean-bin:
	rm -f nflog_dns

clean-deb:
	dh_clean

clean-rpm:
	rm -rf ${HOME}/rpmbuild/BUILD/nflog-dns-*
	rm -f ${HOME}/rpmbuild/SOURCES/nflog-dns-*.tar.gz
	rm -f ${HOME}/rpmbuild/SPECS/nflog_dns.spec

clean: clean-bin clean-deb clean-rpm

distclean: clean

run-tests:
	bash ./test/run_tests.sh

test: run-tests

install-bin:
	install -s -Dm755 "nflog_dns" "$(DESTDIR)$(SBINDIR)/nflog_dns"

install-init:
ifeq ($(INSTALL_SYSVINIT),1)
	install -Dm755 "init.d/nflog_dns"  "$(DESTDIR)$(ETCDIR)/init.d/nflog_dns"
	sed -i 's#^DAEMON=.*#DAEMON="$(SBINDIR)/nflog_dns"#' "$(DESTDIR)$(ETCDIR)/init.d/nflog_dns"
endif

install-systemd:
ifeq ($(INSTALL_SYSTEMD),1)
	install -Dm644 "systemd/nflog_dns.service" "$(DESTDIR)$(PREFIX)/lib/systemd/system/nflog_dns.service"
endif

CONFIG_FILES := default/nflog_dns
install-config:
	$(foreach file, $(CONFIG_FILES), \
		test -e "$(DESTDIR)$(ETCDIR)/$(file)" || install -v -Dm644 "$(file)" "$(DESTDIR)$(ETCDIR)/$(file)";)

install: install-bin install-init install-systemd install-config

.PHONY: all clean distclean run-tests test install-bin install-init install-systemd install-config install deb rpm
