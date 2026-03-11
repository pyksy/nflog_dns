# nflog_dns

DNS packet syslogging using iptables NFLOG, written in C++. This program
parses DNS reply packets and logs the details (any combination of
A, AAAA, CNAME, MX, PTR, TXT records and FORMERR, SERVFAIL, NXDOMAIN,
NOTIMPL, REFUSED errors) to syslog or console (stdout).

## .deb/.rpm packages

Prebuilt .deb/.rpm packages for popular distributions can be downloaded from the Releases page.

## Requirements

nflog_dns requires libfmt, libtins, libnetfilter_log and libspdlog libraries

## Compile (Debian based distributions)

1. sudo apt-get install build-essential libtins-dev libnetfilter-log-dev libspdlog-dev
2. make

## Compile (RPM based distributions)

1. sudo dnf install gcc-c++ make libpcap-devel libtins-devel libnetfilter_log-devel spdlog-devel
2. make

## Run tests (Debian based distributions)

1. sudo apt-get install doctest-dev
2. sudo make test

## Run tests (RPM based distributions)

1. sudo dnf install doctest-devel
2. sudo make test

## Quickstart

1. Compile nflog_dns as above
2. sudo ./start.sh
3. sudo ./nflog_dns
4. Make some DNS queries and observe the extracted DNS replies
5. sudo ./stop.sh

## Install

1. Compile nflog_dns as above
2. Optional: Edit the PREFIX in Makefile. By default installs to /usr/local
3. sudo make install

## Enable sysvinit service

1. Install nflog_dns as above
2. Edit options in /etc/default/nflog_dns to suit your needs
3. sudo update-rc.d nflog_dns defaults
4. sudo service nflog_dns start

## Enable systemd service

1. Install nflog_dns as above
2. Edit options in /etc/default/nflog_dns to suit your needs
3. sudo systemctl enable nflog_dns.service
4. sudo systemctl start nflog_dns.service

## Build deb package

1. sudo apt-get install debhelper-compat lsb-release (plus compile dependencies from above)
2. make deb

## Build rpm package

1. sudo dnf install rpm-build rpmdevtools (plus compile dependencies from above)
2. make rpm

## Usage

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
      --log-a=BOOL         A record logging (default: yes)
      --log-aaaa=BOOL      AAAA record logging (default: yes)
      --log-cname=BOOL     CNAME record logging (default: yes)
      --log-mx=BOOL        MX record logging (default: yes)
      --log-ptr=BOOL       PTR record logging (default: yes)
      --log-txt=BOOL       TXT record logging (default: yes)
      --log-noerror=BOOL   NOERROR replies logging (default: yes)
      --log-formerr=BOOL   FORMERR error logging (default: no)
      --log-servfail=BOOL  SERVFAIL error logging (default: no)
      --log-nxdomain=BOOL  NXDOMAIN error logging (default: no)
      --log-notimpl=BOOL   NOTIMPL error logging (default: no)
      --log-refused=BOOL   REFUSED error logging (default: no)
```

## iptables setup

Add an iptables rule to send packets to NFLOG group 123:

**IPv4:**
```bash
sudo iptables -A INPUT -p udp --sport 53 -j NFLOG --nflog-group 123
```

**IPv6:**
```bash
sudo ip6tables -A INPUT -p udp --sport 53 -j NFLOG --nflog-group 123
```

## nftables setup

Add an nftables rule to send packets to NFLOG group 123:

```bash
sudo nft add rule inet filter input udp sport 53 log group 123
```

## Known issues

[A bug in libtins ip6.arpa PTR reply parsing](https://github.com/mfontanini/libtins/issues/551)
prevents logging IPv6 reverse DNS lookups.

## Create a new release

1. Run the create_release.sh script
