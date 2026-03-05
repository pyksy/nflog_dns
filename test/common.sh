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
	notimpl
	refused
)
declare -a INVALID_TYPES=(
	emptypacket
	badip
	malformed
	noquestion
	query
)
