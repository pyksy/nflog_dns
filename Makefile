all:
	g++ nflog_sniff.cpp -std=c++11 -ltins -lnetfilter_log -lfmt -lspdlog -o nflog_sniff
