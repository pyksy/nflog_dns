# nflog_dns

DNS packet logging utilizing iptables NFLOG target, written in C++. This program
parses DNS reply packets and logs the details to syslog or console (stdout),
in plaintext or in JSON format. Supports mostly all query types (A, CNAME, PTR, ...)
and return codes (NOERROR, NXDOMAIN, REFUSED, ...).

## Usage

```
% nflog_dns -h
Usage: nflog_dns [OPTION]...

Extract DNS replies from NFLOG group

  -f, --facility=FACILITY  facility for syslog logging (default: user)
  -g, --group=NUM          NFLOG group to bind (default: 123)
  -h, --help               print this help and exit
  -j, --json               output in json format
  -l, --loglevel=LOGLEVEL  log level for syslog logging (default: info)
  -q, --qtype=QTYPE,...    log QTYPE type DNS replies (default: A,AAAA)
  -r, --rcode=RCODE,...    log RCODE return code replies (default: NOERROR)
  -s, --syslog             log replies to syslog instead of stdout
  -u, --user=USER          user after dropping privileges (default: nobody)
  -v, --version            show version and exit
```
See nflog_dns.8 manpage for further information, including explanation of command line options.

## .deb/.rpm packages

Prebuilt .deb/.rpm packages for popular distributions can be downloaded from the Releases page.

## APT repository

Released .deb packages are also available via APT repository.

Add APT signing key, then add APT source, then update APT sources, then install package nflog-dns. Replace 'trixie' with your distribution name.
```
curl -fsSL https://pyksy.github.io/nflog_dns/apt/nflog-dns-archive-keyring.asc \
    | sudo gpg --dearmor -o /usr/share/keyrings/nflog-dns-archive-keyring.gpg -
echo 'deb [signed-by=/usr/share/keyrings/nflog-dns-archive-keyring.gpg] \
    https://pyksy.github.io/nflog_dns/apt trixie main' \
    | sudo tee /etc/apt/sources.list.d/nflog-dns.list
sudo apt-get update
sudo apt-get install nflog-dns
```

## RPM Repository

Released .rpm packages are also available via RPM repository.

### Fedora Core

Add .repo file to yum and install nflog_dns. Replace 'fc44' with your distribution name.
```
sudo curl -sSfL -o /etc/yum.repos.d/nflog-dns.repo \
    https://pyksy.github.io/nflog_dns/rpm/fc44/x86_64/nflog-dns.repo
sudo dnf install nflog_dns
```

### openSUSE

#### Leap

Add nflog_dns and netfilter repos zypper and refresh, then install nflog_dns.
Replace 'leap160' / '16.0' with your Leap distribution name / version.
```
sudo zypper addrepo https://pyksy.github.io/nflog_dns/rpm/leap160/x86_64/nflog-dns.repo
sudo zypper addrepo https://download.opensuse.org/repositories/security:netfilter/16.0/security:netfilter.repo
sudo zypper refresh
sudo zypper install nflog_dns
```

#### Tumbleweed

Add nflog_dns repo zypper and refresh, then install nflog_dns.
```
sudo zypper addrepo https://pyksy.github.io/nflog_dns/rpm/tumbleweed/x86_64/nflog-dns.repo
sudo zypper refresh
sudo zypper install nflog_dns
```

## Requirements

Building nflog_dns requires libfmt, libtins, libnetfilter_log and libspdlog libraries.

Building unit tests also requires doctest.

Building .deb packages also requires debhelper-compat and lsb-release.

Building .rpm packages also requires rpm-build and rpmdevtools.

## Compile (Debian based distributions)

```
sudo apt-get install build-essential libtins-dev libnetfilter-log-dev libspdlog-dev libfmt-dev
make
```

## Compile (RPM based distributions)

```
sudo dnf install gcc-c++ make libpcap-devel libtins-devel libnetfilter_log-devel spdlog-devel
make
```

## Run tests (Debian based distributions)

```
sudo apt-get install doctest-dev
sudo make test
```

## Run tests (RPM based distributions)

```
sudo dnf install doctest-devel
sudo make test
```

## Quickstart demo

Compile nflog_dns as above, then
```
sudo ./start.sh
sudo ./nflog_dns
```
Make some DNS queries and observe the extracted DNS replies. CTRL-C stops nflog_dns.
```
sudo ./stop.sh
```

## Install

Compile nflog_dns as above. Optional: Edit the PREFIX in Makefile. By default installs to /usr/local.
```
sudo make install
```

## Enable sysvinit service

Install nflog_dns as above, then edit options in /etc/default/nflog_dns to suit your needs.

Enable and start nflog_dns service:
```
sudo update-rc.d nflog_dns defaults
sudo service nflog_dns start
```

## Enable systemd service

Install nflog_dns as above, then edit options in /etc/default/nflog_dns to suit your needs.

Enable and start nflog_dns service:
```
sudo systemctl enable nflog_dns.service
sudo systemctl start nflog_dns.service
```

## Build .deb package

```
sudo apt-get install debhelper-compat lsb-release
make deb
```

## Build .rpm package


```
sudo dnf install rpm-build rpmdevtools
make rpm
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

In GitHub Actions, trigger manual build ("Run workflow") and select "Create a release" from dropdown menu.
