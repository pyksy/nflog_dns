#!/bin/bash

# Copyright Antti Kultanen <antti.kultanen@molukki.com>
# nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file

set -e

source common.sh

FAIL_COUNT=0

check_result() {
	if [ "$1" -eq 0 ]
	then
		echo "SUCCESS"
	else

		FAIL_COUNT=$((FAIL_COUNT+1))
		echo "FAIL"
	fi
}

echo -n "Verify nflog_dns implicitly drops privileges to user 'nobody'... "
"${DIR}/../nflog_dns" >/dev/null &
NFLOGPID="${!}"
sleep 1
NFLOG_USER="$(ps -o user= -p ${NFLOGPID})"
kill -HUP ${NFLOGPID}
[[ "${NFLOG_USER}" == "nobody" ]]
check_result $?

echo -n "Verify nflog_dns explicitly drops privileges to user 'nobody'... "
"${DIR}/../nflog_dns" --user=nobody >/dev/null &
NFLOGPID="${!}"
sleep 1
NFLOG_USER="$(ps -o user= -p ${NFLOGPID})"
kill -HUP ${NFLOGPID}
[[ "${NFLOG_USER}" == "nobody" ]]
check_result $?

echo -n "Verify nflog_dns explicitly runs as 'root'... "
"${DIR}/../nflog_dns" --user=root >/dev/null &
NFLOGPID="${!}"
sleep 1
NFLOG_USER="$(ps -o user= -p ${NFLOGPID})"
kill -HUP ${NFLOGPID}
[[ "${NFLOG_USER}" == "root" ]]
check_result $?

RANDOM_USER="nflog_$(tr -dc 'a-z0-9' < /dev/urandom | head -c 10)"
echo -n "Verify nflog_dns refuses to drop privileges to non-existing user '${RANDOM_USER}'... "
"${DIR}/../nflog_dns" --user="${RANDOM_USER}" >/dev/null 2>&1 &
NFLOGPID="${!}"
sleep 1
if ps -p ${NFLOGPID} >/dev/null
then
	kill -HUP ${NFLOGPID}
	check_result 1
else
	check_result 0
fi

echo "done"
echo

exit $FAIL_COUNT
