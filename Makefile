PREFIX := /usr/local
ETCDIR := /etc

all:
	g++ nflog_sniff.cpp -std=c++11 -ltins -lnetfilter_log -lfmt -lspdlog -o nflog_sniff

clean:
	rm -f nflog_sniff

distclean: clean

install-bin:
	install -Dm755 "nflog_sniff" "$(PREFIX)/sbin/nflog_sniff"

install-init:
	install -Dm755 "init.d/nflog_sniff"  "$(ETCDIR)/init.d/nflog_sniff"

CONFIG_FILES := default/nflog_sniff
install-config:
	$(foreach file, $(CONFIG_FILES), \
		test -e "$(ETCDIR)/$(file)" || install -v -Dm644 "$(file)" "$(ETCDIR)/$(file)";)

install: install-bin install-init install-config
