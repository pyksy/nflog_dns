# nflog_dns

DNS packet syslogging using iptables NFLOG, written in C++. This program
parses A, AAAA and PTR type DNS reply packets and logs the details to syslog or console.

# .deb/.rpm packages

Prebuilt .deb/.rpm packages for popular distributions can be downloaded from the Releases page.

# requirements

nflog_dns requires libfmt, libtins, libnetfilter_log and libspdlog libraries

# compile

1. sudo apt-get install build-essential libtins-dev libnetfilter-log-dev libspdlog-dev
2. make

# run tests

1. sudo make test

# quickstart

1. sudo ./start.sh
2. sudo ./nflog_dns
3. Make some DNS queries and observe the extracted names and IPs

# build deb package

1. make deb

# build rpm package

1. make rpm

# install

1. Compile nflog_dns as above
2. Optional: Edit the PREFIX in Makefile. By default installs to /usr/local
3. sudo make install

# enable sysvinit service

1. Install nflog_dns as above
2. Edit options in /etc/default/nflog_dns to suit your needs
3. sudo update-rc.d nflog_dns defaults
4. sudo service nflog_dns start

# enable systemd service

1. Install nflog_dns as above
2. Edit options in /etc/default/nflog_dns to suit your needs
3. sudo systemctl enable nflog_dns.service
4. sudo systemctl start nflog_dns.service

# usage
```
% nflog_dns -h
Usage: nflog_dns [OPTION]...

Extract DNS replies from NFLOG group

  -g, --group=NUM          NFLOG group to bind (default: 123)
  -s, --syslog             log replies to syslog instead of stdout
  -f, --facility=FACILITY  facility for syslog logging (default: user)
  -l, --level=LOGLEVEL     log level for syslog logging (default: info)
  -h, --help               print this help and exit
  -v, --version            show version and exit
      --a=BOOL             A record logging (default: yes)
      --aaaa=BOOL          AAAA record logging (default: yes)
      --cname=BOOL         CNAME record logging (default: yes)
      --ptr=BOOL           PTR record logging (default: yes)
```

# iptables setup
To log DNS replies, add an iptables rule to send packets to NFLOG group 123:

**IPv4:**
```bash
sudo iptables -A INPUT -p udp --sport 53 -j NFLOG --nflog-group 123
```

**IPv6:**
```bash
sudo ip6tables -A INPUT -p udp --sport 53 -j NFLOG --nflog-group 123

# known issues

[A bug in libtins ip6.arpa PTR reply parsing](https://github.com/mfontanini/libtins/issues/551) 
prevents logging IPv6 reverse DNS lookups.

# create a new release

1. Run the create_release.sh script
