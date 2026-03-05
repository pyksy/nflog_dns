#!/bin/bash

# Copyright Antti Kultanen <antti.kultanen@molukki.com>
# nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file

set -e

source common.sh

verify_logging_options() {
	echo "Verify logging options can be set to '${1}'... "
	for LOGOPT in "${PACKET_TYPES[@]}" "${NOERROR_TYPES[@]}" "${ERROR_TYPES[@]}"
	do
		"${DIR}/../nflog_dns" --log-"${LOGOPT}"="${1}" --help | grep -- "--log-${LOGOPT}=.*\(default: ${1}\)"
	done
	echo "done"
}

# Verify cmdline logging options work
verify_logging_options yes
((fail_count == 0)) || exit 1
verify_logging_options no
((fail_count == 0)) || exit 1
