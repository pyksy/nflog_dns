# nflog_sniff
DNS packet sniffing with NFLOG in C++.

# requirements

nflog_sniff.cpp requires libtins, libnetfilter_log and spdlog libraries

# compile

1. sudo apt-get install libtins-dev libnetfilter-log-dev spdlog-dev
2. make

# quickstart

1. ./start.sh
2. sudo ./nflog_sniff
3. make some DNS queries and observe the extracted names and IPs

# install

Edit the PREFIX in Makefile if needed. The default is to install in /usr/local

1. compile as above
2. sudo make install

# enable service

1. install as above
2. edit options in /etc/default/nflog_sniff as needed
3. sudo update-rc.d nflog_sniff defaults
4. sudo service nflog_sniff start
