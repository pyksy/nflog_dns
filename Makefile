# Written by Andreas Jaggi <andreas.jaggi@waterwave.ch> in December 2015
# Written by Antti Kultanen <antti.kultanen@molukki.com> since August 2025
#
# nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file

PREFIX ?= /usr/local
ETCDIR ?= /etc
SBINDIR ?= $(PREFIX)/sbin
CXX ?= c++
CXXFLAGS ?= -O2 -std=c++11 -Wall -Wextra -Werror -pedantic -DSPDLOG_FMT_EXTERNAL
CXXEXTRAFLAGS ?= 
INSTALL_SYSVINIT ?= 1
INSTALL_SYSTEMD ?= 1
SOURCES = config.cpp nflog_dns.cpp
HEADERS = config.h version.h

all:
	$(CXX) $(CXXFLAGS) $(CXXEXTRAFLAGS) $(SOURCES) -I/usr/include/libnetfilter_log -ltins -lnetfilter_log -lfmt -lspdlog -o nflog_dns

deb:
	dpkg-buildpackage -us -uc -b

rpm: nflog_dns.spec
	$(eval VERSION := $(shell grep '#define PROGRAM_VERSION' version.h | cut -d'"' -f2))
	mkdir -p ${HOME}/rpmbuild/SOURCES ${HOME}/rpmbuild/SPECS
	tar czf ${HOME}/rpmbuild/SOURCES/nflog_dns-$(VERSION).tar.gz \
		--exclude=.git --exclude=debian --exclude='*.deb' --exclude='*.rpm' \
		--transform 's,^\.,nflog_dns-$(VERSION),' .
	sed 's/^Version:.*/Version:        $(VERSION)/' nflog_dns.spec > ${HOME}/rpmbuild/SPECS/nflog_dns.spec
	rpmbuild -ba --define "_topdir ${HOME}/rpmbuild" ${HOME}/rpmbuild/SPECS/nflog_dns.spec

debug: CXXEXTRAFLAGS = -g -fsanitize=address
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

install-bin-debug:
	install -Dm755 "nflog_dns" "$(DESTDIR)$(SBINDIR)/nflog_dns"

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

install-files: install-init install-systemd install-config

install: install-bin install-files

install-debug: install-bin-debug install-files

uninstall-bin:
	rm -f "$(DESTDIR)$(SBINDIR)/nflog_dns"

uninstall-init:
ifeq ($(INSTALL_SYSVINIT),1)
	rm -f "$(DESTDIR)$(ETCDIR)/init.d/nflog_dns"
endif

uninstall-systemd:
ifeq ($(INSTALL_SYSTEMD),1)
	rm -f "$(DESTDIR)$(PREFIX)/lib/systemd/system/nflog_dns.service"
endif

uninstall-config:
	$(foreach file, $(CONFIG_FILES), \
		rm -f "$(DESTDIR)$(ETCDIR)/$(file)";)

uninstall-files: uninstall-init uninstall-systemd uninstall-config

uninstall: uninstall-bin uninstall-files

.PHONY: all deb rpm \
	clean distclean \
	run-tests test \
	install-bin install-bin-debug \
	install-init install-systemd install-config install-files \
	install install-debug \
	uninstall-bin \
	uninstall-init uninstall-systemd uninstall-config uninstall-files \
	uninstall
