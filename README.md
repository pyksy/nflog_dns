# nflog_dns
DNS packet syslogging using iptables NFLOG, written in C++. This program
parses A, AAAA and PTR type DNS reply packets and logs the details to syslog or console.

# requirements

nflog_dns.cpp requires libtins, libnetfilter_log and libspdlog libraries

# compile

1. sudo apt-get install build-essential libtins-dev libnetfilter-log-dev libspdlog-dev
2. make

# quickstart

1. sudo ./start.sh
2. sudo ./nflog_dns
3. Make some DNS queries and observe the extracted names and IPs

# build deb package

1. make deb

# install

1. Compile nflog_dns as above
2. Optional: Edit the PREFIX in Makefile. By default installs to /usr/local
3. sudo make install

# enable sysvinit service

1. Install nflog_dns as above
2. Edit options in /etc/default/nflog_dns to suit your needs
3. sudo update-rc.d nflog_dns defaults
4. sudo service nflog_dns start

# run tests

1. sudo make test

# known issues

[A bug in libtins ip6.arpa PTR reply parsing](https://github.com/mfontanini/libtins/issues/551) 
prevents logging IPv6 reverse DNS lookups.
