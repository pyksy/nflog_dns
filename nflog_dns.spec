Name:           nflog_dns
Version:        0.0.0
Release:        1%{?dist}
Summary:        Extract and log DNS replies from NFLOG group

License:        GPL-2.0-or-later
URL:            https://github.com/pyksy/nflog_dns
Source0:        %{name}-%{version}.tar.gz

BuildRequires: gcc-c++
BuildRequires: make
BuildRequires: libtins-devel
BuildRequires: libnetfilter_log-devel
BuildRequires: spdlog-devel
BuildRequires: libpcap-devel
BuildRequires: fmt-devel
BuildRequires: systemd-rpm-macros

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
%make_install PREFIX=%{_prefix} ETCDIR=%{_sysconfdir} SBINDIR=%{_sbindir} INSTALL_SYSVINIT=0

%check
# Tests require root and cannot be run during rpm build
# make test

%files
%license LICENSE
%doc README.md
%{_sbindir}/nflog_dns
%{_unitdir}/nflog_dns.service
%config(noreplace) %{_sysconfdir}/default/nflog_dns

%post
%systemd_post nflog_dns.service

%preun
%systemd_preun nflog_dns.service

%postun
%systemd_postun_with_restart nflog_dns.service

%changelog
* Wed Jan 14 2026 Antti Kultanen <antti.kultanen@molukki.com> - 0.9.999-1
- Fix release script
- Fix readme
- Properly update rpm .spec when creating a release
- List package contents in QA
- Repair .spec changelog
- Ship README.md in .deb package docs
- Update readme
- Properly update debian/changelog when creating a release
- Repair debian/changelog
- Fixes to release script
- Add .gitignore
- Minor fixes

* Sun Jan 11 2026 Antti Kultanen <antti.kultanen@molukki.com> - 0.9.99-1
- Code fixes
- Fix indentation
- Fix arm64 dbgsym
- Update README
- Add header guard
- Update readme
- Update CI
- Makefile improvements
- Touch up defaults config
- Increase nflog buffer size
- Remove redundant resource check
- Handle resources on error

* Thu Nov 27 2025 Antti Kultanen <antti.kultanen@molukki.com> - 0.9.9-1
- Add DEB testing to QA build

* Thu Nov 20 2025 Antti Kultanen <antti.kultanen@molukki.com> - 0.9.1-1
- Add Fedora 43 build, drop Fedora 41
- Add re-install step
- Add maintainer scripts
- Update tests
- Update help, split defaults to config.h
- Add usage to README
- Add cmdline args for record types

* Thu Nov 13 2025 Antti Kultanen <antti.kultanen@molukki.com> - 0.9.0-1
- Fix package naming
- Add OpenSUSE Leap 16.0 build, drop 15.6 build (#1)
- Update CI
- Minor build optimizations
- Release message wording

* Mon Nov 03 2025 Antti Kultanen <antti.kultanen@molukki.com> - 0.0.9-1
- Bump version to 0.0.9
- Add Devuan 6.0 (excalibur) stable build, drop Devuan 4.0 oldoldstable build

* Thu Oct 23 2025 Antti Kultanen <antti.kultanen@molukki.com> - 0.0.8-1
- Bump version to 0.0.8
- Typo fix
- Add systemd-rpm-macros dependency, update release note

* Mon Oct 13 2025 Antti Kultanen <antti.kultanen@molukki.com> - 0.0.7-1
- Bump version to 0.0.7
- Fix fox release note redux
- Fix for release note
- CodeQL scan
- Devuan updates
- Caching fixes
- Release note body
- RPi build revamp
- Workflow update
- Runner fix
- Runner archs
- Arm64 ubuntu
- Update Devuan build
- No releases for daily builds

* Fri Oct 10 2025 Antti Kultanen <antti.kultanen@molukki.com> - 0.0.6-1
- Bump version to 0.0.6
- Add Devuan builds
- Fixes and updates to package builds
- opensuse package test fix
- Fix CI
- Add asan for test build, verify package install
- Code quality fixes
- Update copyright notices

* Thu Oct 09 2025 Antti Kultanen <antti.kultanen@molukki.com> - 0.0.5-1
- Bump version to 0.0.5
- No artifact upload for commits
- Fix opensuse builds, remove git from pkgbuild dependencies, other minor fixes

* Wed Oct 08 2025 Antti Kultanen <antti.kultanen@molukki.com> - 0.0.4-1
- Bump version to 0.0.4
- Update README for rpm package
- Schedule nightly builds
- Update copyright notices

* Wed Oct 08 2025 Antti Kultanen <antti.kultanen@molukki.com> - 0.0.3-1
- Bump version to 0.0.3
- Modify release pkg versioning

* Wed Oct 08 2025 Antti Kultanen <antti.kultanen@molukki.com> - 0.0.2-1
- Bump version to 0.0.2
- Add release script

* Tue Oct 07 2025 Antti Kultanen <antti.kultanen@molukki.com> - 0.0.1-1
- Bump version to 0.0.1
- Release creation
- Add builds for raspberry pi, upload builds from commits
- RPM fix for suse
- Build rpms for Fedora, openSUSE and add deb builds for Ubuntu
- Build packages in containers
- version.h

* Sun Oct 05 2025 Antti Kultanen <antti.kultanen@molukki.com> - 0.0.0-1
- Initial RPM package
