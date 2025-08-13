# nflog_sniff
DNS packet sniffing with NFLOG in C++.

# requirements

nflog_sniff.cpp requires libtins, libnetfilter_log and spdlog libraries

# compile

1. apt-get install libtins-dev libnetfilter-log-dev spdlog-dev
2. make

# quickstart

1. start.sh
2. sudo ./nflog_sniff
3. make some DNS queries and observe the extracted names and IPs

