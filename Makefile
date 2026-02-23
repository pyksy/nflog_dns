# Written by Andreas Jaggi <andreas.jaggi@waterwave.ch> in December 2015
# Written by Antti Kultanen <antti.kultanen@molukki.com> since August 2025
#
# nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file

PREFIX ?= /usr/local
ETCDIR ?= /etc
SBINDIR ?= $(PREFIX)/sbin
RPMBUILDDIR ?= $(HOME)/rpmbuild
CXX ?= c++
CXXFLAGS ?= -O2 -std=c++11 -Wall -Wextra -Werror -pedantic
CXXFLAGS += $(shell pkg-config --cflags libnetfilter_log libtins fmt spdlog)
CXXEXTRAFLAGS ?=
LDFLAGS ?=
LIBS ?= $(shell pkg-config --libs libnetfilter_log libtins fmt spdlog)
INSTALL_SYSVINIT ?= 1
INSTALL_SYSTEMD ?= 1
SOURCES = config.cpp nflog_dns.cpp
HEADERS = config.h version.h

all: nflog_dns

nflog_dns: $(SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) $(CXXEXTRAFLAGS) $(LDFLAGS) $(SOURCES) $(LIBS) -o $@

deb:
	dpkg-buildpackage -us -uc -b

rpm: nflog_dns.spec
	$(eval VERSION := $(shell awk -F'"' '/PROGRAM_VERSION/ {print $$2}' version.h))
	mkdir -p "$(RPMBUILDDIR)"/SOURCES "$(RPMBUILDDIR)"/SPECS
	tar czf "$(RPMBUILDDIR)"/SOURCES/nflog_dns-$(VERSION).tar.gz \
		--exclude=.git --exclude=debian --exclude='*.deb' --exclude='*.rpm' \
		--transform 's,^\.,nflog_dns-$(VERSION),' .
	sed 's/^Version:.*/Version:        $(VERSION)/' nflog_dns.spec > "$(RPMBUILDDIR)"/SPECS/nflog_dns.spec
	rpmbuild -ba --define "_topdir $(RPMBUILDDIR)" "$(RPMBUILDDIR)"/SPECS/nflog_dns.spec

debug: CXXFLAGS = -g -O0 -std=c++11 -Wall -Wextra -Werror -pedantic -fsanitize=address -fsanitize=undefined
debug: CXXFLAGS += $(shell pkg-config --cflags libnetfilter_log libtins fmt spdlog)
debug: LDFLAGS += -fsanitize=address -fsanitize=undefined
debug: nflog_dns

clean-bin:
	rm -f nflog_dns

clean-deb:
	@if [ -f debian/debhelper-build-stamp ]; then dh_clean; fi

clean-rpm:
	rm -rf "$(RPMBUILDDIR)"/BUILD/nflog_dns-*
	rm -f "$(RPMBUILDDIR)"/SOURCES/nflog_dns-*.tar.gz
	rm -f "$(RPMBUILDDIR)"/SPECS/nflog_dns.spec
	rm -f "$(RPMBUILDDIR)"/RPMS/*/nflog_dns-*.rpm
	rm -f "$(RPMBUILDDIR)"/SRPMS/nflog_dns-*.src.rpm

clean: clean-bin clean-deb clean-rpm

distclean: clean

run-tests:
	bash ./test/run_tests.sh

test: run-tests

check: test

install-bin:
	install -Dm755 "nflog_dns" "$(DESTDIR)$(SBINDIR)/nflog_dns"

install-bin-strip:
	install -s -Dm755 "nflog_dns" "$(DESTDIR)$(SBINDIR)/nflog_dns"

install-man:
	install -Dm644 "man8/nflog_dns.8" "$(DESTDIR)$(PREFIX)/share/man/man8/nflog_dns.8"
	gzip -f "$(DESTDIR)$(PREFIX)/share/man/man8/nflog_dns.8"

install-init:
ifeq ($(INSTALL_SYSVINIT),1)
	install -Dm755 "init.d/nflog_dns"  "$(DESTDIR)$(ETCDIR)/init.d/nflog_dns"
	sed -i 's#^DAEMON=.*#DAEMON="$(SBINDIR)/nflog_dns"#' "$(DESTDIR)$(ETCDIR)/init.d/nflog_dns"
endif

install-systemd:
ifeq ($(INSTALL_SYSTEMD),1)
	install -Dm644 "systemd/nflog_dns.service" "$(DESTDIR)$(PREFIX)/lib/systemd/system/nflog_dns.service"
	sed -i 's#^ExecStart=.*#ExecStart=$(SBINDIR)/nflog_dns $$OPTIONS#' "$(DESTDIR)$(PREFIX)/lib/systemd/system/nflog_dns.service"
endif

CONFIG_FILES := default/nflog_dns
install-config:
	$(foreach file, $(CONFIG_FILES), \
		test -e "$(DESTDIR)$(ETCDIR)/$(file)" || install -v -Dm644 "$(file)" "$(DESTDIR)$(ETCDIR)/$(file)" || exit 1;)

install-files: install-init install-systemd install-config

install: install-bin install-man install-files

install-strip: install-bin-strip install-files

uninstall-bin:
	rm -f "$(DESTDIR)$(SBINDIR)/nflog_dns"

uninstall-man:
	rm -f "$(DESTDIR)$(PREFIX)/share/man/man8/nflog_dns.8.gz"

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

uninstall: uninstall-bin uninstall-man uninstall-files

.PHONY: all nflog_dns deb rpm \
	clean distclean \
	run-tests test check \
	install-bin install-bin-strip \
	install-man \
	install-init install-systemd install-config install-files \
	install install-strip \
	uninstall-bin \
	uninstall-man \
	uninstall-init uninstall-systemd uninstall-config uninstall-files \
	uninstall
