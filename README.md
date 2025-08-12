# nflog_sniff
DNS packet sniffing with NFLOG in C++.

# requirements

nflog_sniffer.cpp requires libtins and libnetfilter_log

# compile

1. apt-get install libtins-dev libnetfilter-log-dev
2. make

# quickstart

1. start.sh
2. sudo ./nflog_sniffer
3. make some DNS queries and observe the extracted names and IPs

