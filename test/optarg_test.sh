#!/bin/bash

# Copyright Antti Kultanen <antti.kultanen@molukki.com>
# nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file

set -e

source common.sh

fail_count=0

# A valid --qtype/--rcode value must be accepted: the parser returns control
# to the getopt loop and --help still runs to completion (exit 0), instead
# of the process erroring out during option parsing.
verify_accepted() {
	local OPTION="${1}"
	local VALUE="${2}"
	echo -n "Verify ${OPTION}=${VALUE} is accepted... "
	if "${DIR}/../nflog_dns" "${OPTION}=${VALUE}" --help >/dev/null 2>&1
	then
		echo "SUCCESS"
	else
		echo "FAIL"
		((fail_count++))
	fi
}

# An invalid --qtype/--rcode value must be rejected: nonzero exit and the
# expected message on stderr, and it must never reach --help output.
verify_rejected() {
	local OPTION="${1}"
	local VALUE="${2}"
	local EXPECTED_MSG="${3}"
	echo -n "Verify ${OPTION}=${VALUE} is rejected... "
	OUTPUT="$("${DIR}/../nflog_dns" "${OPTION}=${VALUE}" --help 2>&1 >/dev/null)" && RC=0 || RC="${?}"
	if [ "${RC}" -ne 0 ] && echo "${OUTPUT}" | grep -qF -- "${EXPECTED_MSG}"
	then
		echo "SUCCESS"
	else
		echo "FAIL"
		((fail_count++))
	fi
}

echo "Verify every supported --qtype value is accepted individually..."
for TYPE in "${ALL_QTYPES[@]}"
do
	verify_accepted --qtype "${TYPE}"
done
echo "done"
echo

echo "Verify every supported --rcode value is accepted individually..."
for CODE in "${ALL_RCODES[@]}"
do
	verify_accepted --rcode "${CODE}"
done
echo "done"
echo

echo "Verify --qtype/--rcode accept comma-separated lists..."
verify_accepted --qtype "A,AAAA,MX,TXT"
verify_accepted --rcode "NOERROR,NXDOMAIN,SERVFAIL"
echo "done"
echo

echo "Verify --qtype/--rcode are case-insensitive..."
verify_accepted --qtype "a,aAaA,Mx"
verify_accepted --rcode "noerror,NxDomain"
echo "done"
echo

echo "Verify --qtype/--rcode accept lists with stray commas..."
verify_accepted --qtype ",A,,MX,"
verify_accepted --rcode ",NXDOMAIN,,SERVFAIL,"
echo "done"
echo

echo "Verify --qtype/--rcode accept the ALL selector..."
verify_accepted --qtype "ALL"
verify_accepted --rcode "ALL"
echo "done"
echo

echo "Verify --qtype/--rcode accept an empty value (disables all types/codes)..."
verify_accepted --qtype ""
verify_accepted --rcode ""
echo "done"
echo

echo "Verify --qtype/--rcode reject an unknown value..."
verify_rejected --qtype "BOGUS" "Error: Invalid qtype: unknown DNS qtype: BOGUS"
verify_rejected --rcode "BOGUS" "Error: Invalid rcode: unknown DNS rcode: BOGUS"
echo "done"
echo

echo "Verify --loglevel is accepted..."
verify_accepted --loglevel "debug"
echo "done"
echo

echo -n "Verify old --log-a=yes flag no longer exists (replaced by --qtype/--rcode)... "
"${DIR}/../nflog_dns" --log-a=yes >/dev/null 2>&1 && RC=0 || RC="${?}"
if [ "${RC}" -ne 0 ]
then
	echo "SUCCESS"
else
	echo "FAIL"
	((fail_count++))
fi
echo

((fail_count == 0)) || exit 1
