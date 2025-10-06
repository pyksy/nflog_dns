Name:           nflog-dns
Version:        0.0.0
Release:        1%{?dist}
Summary:        Extract and log DNS replies from NFLOG group

License:        GPL-2.0-or-later
URL:            https://github.com/yourusername/nflog_dns
Source0:        %{name}-%{version}.tar.gz

%global debug_package %{nil}

BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  libtins-devel
BuildRequires:  libnetfilter_log-devel
BuildRequires:  spdlog-devel
BuildRequires:  libpcap-devel
BuildRequires:  fmt-devel

Requires:       libtins
Requires:       libnetfilter_log
Requires:       spdlog
Requires:       libpcap
Requires:       fmt

%description
A tool to extract and log DNS replies from Netfilter NFLOG groups.
The tool binds to an NFLOG group and logs received DNS response records
(A, AAAA, CNAME, PTR) to syslog or stdout.

%prep
%autosetup

%build
%make_build

%install
%make_install PREFIX=%{_prefix} ETCDIR=%{_sysconfdir} SBINDIR=%{_sbindir}

%files
%license LICENSE
%doc README.md
%{_sbindir}/nflog_dns
%{_unitdir}/nflog_dns.service
%{_sysconfdir}/init.d/nflog_dns
%config(noreplace) %{_sysconfdir}/default/nflog_dns

%post
%systemd_post nflog_dns.service

%preun
%systemd_preun nflog_dns.service

%postun
%systemd_postun_with_restart nflog_dns.service

%changelog
* Sun Oct 05 2025 Antti Kultanen <antti.kultanen@molukki.com> - 0.0.0-1
- Initial RPM package
