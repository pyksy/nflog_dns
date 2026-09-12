#!/bin/bash

# Copyright Antti Kultanen <antti.kultanen@molukki.com>
# nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file

DIR="$(dirname $(realpath "${0}"))"
GROUP=$((RANDOM/2+1024))

declare -a PACKET_TYPES=(
	a
	aaaa
	cname
	mx
	ptr
	txt
)
declare -a NOERROR_TYPES=(
	noerror
)
declare -a ERROR_TYPES=(
	formerr
	servfail
	nxdomain
	notimp
	refused
	yxdomain
	yxrrset
	nxrrset
	notauth
	notzone
)
declare -a INVALID_TYPES=(
	emptypacket
	badip
	malformed
	noquestion
	query
)

# DNS record (query) types accepted by --qtype
declare -a ALL_QTYPES=(
	A NS MD MF CNAME SOA MB MG MR NULL WKS PTR HINFO MINFO MX TXT RP AFSDB
	X25 ISDN RT NSAP NSAP-PTR SIG KEY PX GPOS AAAA LOC NXT EID NIMLOC SRV
	ATMA NAPTR KX CERT A6 DNAME SINK OPT APL DS SSHFP IPSECKEY RRSIG NSEC
	DNSKEY DHCID NSEC3 NSEC3PARAM
)

# DNS reply codes accepted by --rcode
declare -a ALL_RCODES=(
	NOERROR FORMERR SERVFAIL NXDOMAIN NOTIMP REFUSED
	YXDOMAIN YXRRSET NXRRSET NOTAUTH NOTZONE
)
